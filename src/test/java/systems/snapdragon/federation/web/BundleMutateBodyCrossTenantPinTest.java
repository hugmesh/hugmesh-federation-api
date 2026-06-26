package systems.snapdragon.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.federation.testsupport.TestIssuer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Finding [2] end-to-end proof: cross-tenant isolation of the owner-or-admin
 * MUTATING + read-own-body bundle surface — {@code DELETE /api/federation/bundles/{slug}},
 * the {@code PUT /api/federation/bundles/{slug}} supersede step, and
 * {@code GET /api/federation/bundles/slug/{slug}/body} — at the HTTP boundary, through
 * the REAL production {@link systems.snapdragon.federation.config.SecurityConfig} filter
 * chain with REAL RS256 per-brand tokens (two in-process {@link TestIssuer} JWKS
 * servers), the REAL {@code BundleService}, and a REAL Liquibase-applied store. This is
 * the sibling of {@link BundleMetadataCrossTenantPinTest} (which closed the metadata
 * READS) for the mutate/body surface the metadata fix left brand-blind.
 *
 * <p><b>The gap.</b> The admin branch of {@code activeRowForCaller} /
 * {@code supersedePriorOwned} used the SLUG-ONLY active finder
 * ({@code findFirstBySlugAndSupersededAtIsNull...}), and {@code deleteForOwner} /
 * {@code readOwnBody} never even received the {@link systems.snapdragon.commons.security.PrincipalDomain}
 * scope. Because the {@code user_modules} slug namespace is per-owner (NOT globally
 * unique across brands — see {@link systems.snapdragon.federation.repository.UserModuleActiveOwnerUniqueTest}),
 * a per-domain ROLE_ADMIN of brand-X (a valid ADMIN, but NOT superadmin) could DELETE,
 * read the BODY of, or PUT-supersede brand-Y's active card for the same slug. The cut is
 * a SERVICE-QUERY cut (not a 403 — a brand-X admin IS an admin): the fix pins the
 * per-domain admin's active-row load to {@code DOMAIN_brandx}, so brand-Y's row resolves
 * EMPTY (404 / untouched); only SUPERADMIN reaches across brands.
 *
 * <p><b>Mutation-resistant + FAIL-FIRST.</b> The service is NOT mocked. Each cross-domain
 * DENY pairs the HTTP status with a direct DB re-read proving the brand-Y row is
 * UNCHANGED (not superseded, still active) and that no foreign bytes were streamed.
 * Against the unfixed slug-only admin finder the brand-X admin DELETE would have
 * superseded brand-Y's row, the body read would have returned brand-Y's bytes, and the
 * PUT would have superseded/displaced brand-Y's active card — exactly what these
 * assertions catch.
 *
 * <p>Multi-issuer wiring mirrors {@link CrossDomainWriteIsolationTest} /
 * {@link BundleMetadataCrossTenantPinTest}.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class BundleMutateBodyCrossTenantPinTest extends PostgresTestSupport {

    private static TestIssuer brandX;
    private static TestIssuer brandY;
    private static Path bundlesDir;

    @BeforeAll
    static void issuers() throws Exception {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        bundlesDir = Files.createTempDirectory("fed-bundle-mutate-pin-");
    }

    @AfterAll
    static void stop() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        // DB wiring (r2dbc + liquibase, this class's own isolated PG) comes from
        // PostgresTestSupport's @ServiceConnection container.
        r.add("app.manifest-cache.cassandra.enabled", () -> "false");
        r.add("app.bundles.storage", () -> "filesystem");
        r.add("app.bundles.dir", () -> bundlesDir.toString());
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    // A single slug that exists ACTIVE under BOTH brands (per-owner namespace allows it):
    // brand-Y is the victim, brand-X is the attacker's own brand.
    private static final String SLUG = "shared-card";
    private static final String Y_HASH = "a".repeat(64);
    private static final String X_HASH = "b".repeat(64);
    private static final String ENTRY = "remoteEntry.json";
    private static final String Y_BODY = "{\"brand\":\"y-secret\"}";
    private static final String X_BODY = "{\"brand\":\"x-own\"}";

    @Autowired WebTestClient web;
    @Autowired UserModuleRepository userModules;

    @BeforeEach
    void seed() throws Exception {
        userModules.deleteAll().block();

        // Brand-Y's active card (the victim) — a real version dir so a leaked body would
        // actually stream foreign bytes if the cut were missing.
        Path yDir = bundlesDir.resolve(SLUG).resolve(Y_HASH);
        Files.createDirectories(yDir);
        Files.writeString(yDir.resolve(ENTRY), Y_BODY, StandardCharsets.UTF_8);
        userModules.save(activeRow("alice-y", "file:" + yDir, Y_HASH, "brandy")).block();

        // Brand-X's OWN active card for the SAME slug (different owner => no unique-index
        // collision) so the ALLOW cases prove the guard does not over-block.
        Path xDir = bundlesDir.resolve(SLUG).resolve(X_HASH);
        Files.createDirectories(xDir);
        Files.writeString(xDir.resolve(ENTRY), X_BODY, StandardCharsets.UTF_8);
        userModules.save(activeRow("alice-x", "file:" + xDir, X_HASH, "brandx")).block();
    }

    private static UserModule activeRow(String owner, String versionDir, String hash, String domain) {
        UserModule m = new UserModule();
        m.setOwnerUserId(owner);
        m.setSlug(SLUG);
        m.setVersionDir(versionDir);
        m.setEntryFile(ENTRY);
        m.setContentHash(hash);
        m.setManifestJson("{}");
        m.setVisibility("internal");
        m.setDomain(domain);
        m.setCreatedAt(Instant.now());
        return m;
    }

    // brand-X per-domain ADMIN (issuer-derived DOMAIN_brandx, superadmin=false) — the
    // attacker; every brand admin holds exactly this.
    private static String adminX() { return brandX.mint("admin-x", List.of("admin")); }
    private static String adminY() { return brandY.mint("admin-y", List.of("admin")); }
    private static String superadmin() { return brandX.mint("root", List.of("superadmin")); }

    /** The brand-Y victim row freshly re-read from the DB (active = not superseded). */
    private UserModule victimY() {
        return userModules
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, "alice-y")
                .block();
    }

    /** Stamp {@code superseded_at} on the given owner's active row so the slug's only
     *  remaining active card is the other brand's — sets up a clean cross-domain DENY. */
    private void supersedeOwnRow(String owner) {
        userModules
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, owner)
                .flatMap(m -> { m.setSupersededAt(Instant.now()); return userModules.save(m); })
                .block();
    }

    // ───────────────────────── DELETE /bundles/{slug} ─────────────────────────

    @Test
    void delete_brandXAdmin_cannotDeleteBrandYCard_404_andVictimRowUntouched() {
        // Supersede brand-X's OWN active row so the slug's ONLY active card left is
        // brand-Y's — the attacker has nothing of their own to (legitimately) target.
        supersedeOwnRow("alice-x");

        // CROSS-USER DENY (tenant): the brand-X admin's domain-pinned active load for
        // brandx now resolves EMPTY (brand-Y's row is invisible), so the DELETE 404s.
        web.delete().uri("/api/federation/bundles/" + SLUG)
                .header("Authorization", "Bearer " + adminX())
                .exchange()
                .expectStatus().isNotFound();

        // MUTATION-RESISTANT: brand-Y's row is STILL active (never superseded). Against the
        // unfixed slug-only admin finder this DELETE would have superseded it.
        UserModule victim = victimY();
        assertThat(victim)
                .as("a brand-X admin DELETE must not destroy brand-Y's active card")
                .isNotNull();
        assertThat(victim.getSupersededAt()).isNull();
    }

    @Test
    void delete_brandXAdmin_deletesOwnBrandCard_204_andOwnRowSuperseded() {
        // USER-SITUATIONAL ALLOW: brand-X admin deletes its OWN brand's active card.
        web.delete().uri("/api/federation/bundles/" + SLUG)
                .header("Authorization", "Bearer " + adminX())
                .exchange()
                .expectStatus().isNoContent();

        // own brand row gone-active; brand-Y row UNTOUCHED (the guard scopes the delete).
        assertThat(userModules
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, "alice-x")
                .block())
                .as("the brand-X admin's own active card was superseded")
                .isNull();
        assertThat(victimY())
                .as("deleting the own-brand card must leave brand-Y's card active")
                .isNotNull();
    }

    @Test
    void delete_superadmin_deletesBrandYCard_204() {
        // SUPERADMIN cross-domain ALLOW: the infra super-role reaches brand-Y's card.
        // (brand-X's own row is newest-active; superadmin's un-pinned finder takes the
        // newest active row for the slug, which is brand-X's — so supersede it first to
        // target brand-Y deterministically.)
        supersedeOwnRow("alice-x");

        web.delete().uri("/api/federation/bundles/" + SLUG)
                .header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isNoContent();

        assertThat(victimY())
                .as("superadmin reaches across brands and deletes brand-Y's card")
                .isNull();
    }

    // ───────────────────── GET /bundles/slug/{slug}/body ─────────────────────

    @Test
    void body_brandXAdmin_cannotReadBrandYBytes_404_neverForeignBody() {
        // Supersede brand-X's own row so the only active card is brand-Y's; the brand-X
        // admin's domain-pinned active load then resolves EMPTY -> 404.
        supersedeOwnRow("alice-x");

        String body = web.get().uri("/api/federation/bundles/slug/" + SLUG + "/body")
                .header("Authorization", "Bearer " + adminX())
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(String.class).returnResult().getResponseBody();

        // FAIL-FIRST: against the unfixed admin finder this would have streamed Y_BODY.
        if (body != null) {
            assertThat(body)
                    .as("a brand-X admin must never receive brand-Y's card bytes")
                    .doesNotContain("y-secret");
        }
    }

    @Test
    void body_brandXAdmin_readsOwnBrandBytes_200() {
        // USER-SITUATIONAL ALLOW: brand-X admin reads its OWN brand's card body.
        web.get().uri("/api/federation/bundles/slug/" + SLUG + "/body")
                .header("Authorization", "Bearer " + adminX())
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo(X_BODY);
    }

    @Test
    void body_superadmin_readsBrandYBytes_200() {
        // SUPERADMIN cross-domain ALLOW: reaches brand-Y's card body. Supersede brand-X's
        // newer row so the un-pinned finder lands on brand-Y's row deterministically.
        supersedeOwnRow("alice-x");

        web.get().uri("/api/federation/bundles/slug/" + SLUG + "/body")
                .header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo(Y_BODY);
    }

    // ───────────────────────── PUT /bundles/{slug} (supersede) ─────────────────────────

    @Test
    void put_brandXAdmin_cannotSupersedeBrandYCard_brandYRowStaysActive() {
        // Supersede brand-X's own row so the slug's only active card is brand-Y's.
        supersedeOwnRow("alice-x");

        // CROSS-USER DENY (tenant): brand-X admin PUTs to the slug. The domain-pinned
        // prior-active lookup for brandx finds NOTHING (brand-Y's row is invisible), so the
        // PUT is a first-publish IN BRANDX and brand-Y's active card is NEVER superseded.
        web.put().uri("/api/federation/bundles/" + SLUG)
                .header("Authorization", "Bearer " + adminX())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .bodyValue("{\"brand\":\"x-hijack\"}".getBytes(StandardCharsets.UTF_8))
                .exchange()
                .expectStatus().isOk();

        // MUTATION-RESISTANT: brand-Y's card is STILL active (not displaced). Against the
        // unfixed slug-only supersede it would have been stamped superseded.
        UserModule victim = victimY();
        assertThat(victim)
                .as("a brand-X admin PUT must not displace brand-Y's active card")
                .isNotNull();
        assertThat(victim.getSupersededAt()).isNull();
        assertThat(victim.getContentHash())
                .as("brand-Y's active card content is unchanged")
                .isEqualTo(Y_HASH);

        // and the brand-X admin's own NEW active card landed in brandx.
        UserModule landed = userModules
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, "admin-x")
                .block();
        assertThat(landed).isNotNull();
        assertThat(landed.getDomain()).isEqualTo("brandx");
    }

    @Test
    void put_brandYAdmin_supersedesOwnBrandCard_200() {
        // USER-SITUATIONAL ALLOW: brand-Y admin republishes its OWN brand's card. The
        // domain-pinned prior-active lookup finds brand-Y's row and supersedes it.
        web.put().uri("/api/federation/bundles/" + SLUG)
                .header("Authorization", "Bearer " + adminY())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .bodyValue("{\"brand\":\"y-v2\"}".getBytes(StandardCharsets.UTF_8))
                .exchange()
                .expectStatus().isOk();

        // brand-Y's prior alice-y card was superseded by the admin override (own brand).
        assertThat(userModules
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, "alice-y")
                .block())
                .as("brand-Y admin supersedes its own brand's prior active card")
                .isNull();
    }
}
