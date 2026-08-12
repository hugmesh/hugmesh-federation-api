package systems.hugmesh.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.federation.model.UserModule;
import systems.hugmesh.federation.repository.UserModuleRepository;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.federation.testsupport.TestIssuer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * BUG-B end-to-end proof: cross-tenant + cross-owner isolation of the bundle METADATA
 * reads ({@code GET /api/federation/bundles/slug/{slug}} and
 * {@code GET /api/federation/bundles/{contentHash}}) at the HTTP boundary, through the
 * REAL production {@link systems.hugmesh.federation.config.SecurityConfig} filter
 * chain with REAL RS256 per-brand tokens (two in-process {@link TestIssuer} JWKS
 * servers), the REAL {@code BundleService}, and a REAL Liquibase-applied H2 store
 * (incl. the new changeset 035 domain column). Multi-issuer wiring mirrors
 * {@link CrossDomainWriteIsolationTest} / {@link BundleFetchAnyAuthenticatedPinTest}.
 *
 * <p>The cut is a SERVICE-QUERY cut (not a 403): a per-domain caller's read is loaded
 * pinned to their issuer-derived {@code DOMAIN_<x>} (and, for a non-admin, their
 * ownership), so a foreign brand's (or a same-brand peer's) row resolves EMPTY — a 404
 * for the hash read and an EMPTY list for the slug read; SUPERADMIN reaches all.
 *
 * <p><b>Mutation-resistant + FAIL-FIRST.</b> Against the unfixed code (which used the
 * unscoped {@code findBySlug...} / {@code findByContentHash} and returned the FULL
 * {@code UserModule}) the brand-Y caller WOULD get brand-X's metadata (incl. the
 * {@code versionDir} locator + {@code ownerUserId}); these DENY assertions catch
 * exactly that. The body-shape assertions also fail-first because the unfixed response
 * carried {@code versionDir}/{@code ownerUserId}.
 *
 * <p>NB: the content-hash byte FETCH ({@code /bundles/{hash}/files/{*path}}) is
 * intentionally any-authenticated; {@link #fetch_brandYToken_stillGets200_notWeakened}
 * pins that the fix did NOT tighten that capability-by-hash path (it lives in
 * {@link BundleFetchAnyAuthenticatedPinTest} too — re-asserted here for locality).
 */
@SpringBootTest
@AutoConfigureWebTestClient
class BundleMetadataCrossTenantPinTest extends PostgresTestSupport {

    private static TestIssuer brandX;
    private static TestIssuer brandY;
    private static Path bundlesDir;

    @BeforeAll
    static void issuers() throws Exception {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        bundlesDir = Files.createTempDirectory("fed-bundle-meta-pin-");
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
        // PostgresTestSupport's @ServiceConnection container — H2 url/user/password dropped.
        r.add("app.manifest-cache.cassandra.enabled", () -> "false");
        r.add("app.bundles.storage", () -> "filesystem");
        r.add("app.bundles.dir", () -> bundlesDir.toString());
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    private static final String SLUG = "x-card";
    private static final String HASH = "c".repeat(64);
    private static final String ENTRY = "remoteEntry.json";
    private static final String BODY = "{\"name\":\"x-bundle\"}";
    private static final String VERSION_LOCATOR_MARKER = "x-card/" + HASH; // must never appear on the wire

    @Autowired WebTestClient web;
    @Autowired UserModuleRepository userModules;

    @BeforeEach
    void seed() throws Exception {
        userModules.deleteAll().block();
        // A REAL version dir so the byte FETCH can resolve, and a brand-X-owned row.
        Path versionDir = bundlesDir.resolve(SLUG).resolve(HASH);
        Files.createDirectories(versionDir);
        Files.writeString(versionDir.resolve(ENTRY), BODY, StandardCharsets.UTF_8);

        UserModule m = new UserModule();
        m.setOwnerUserId("alice-x");      // owner is a brand-X user
        m.setSlug(SLUG);
        m.setVersionDir("file:" + versionDir);
        m.setEntryFile(ENTRY);
        m.setContentHash(HASH);
        m.setManifestJson("{}");
        m.setVisibility("internal");
        m.setDomain("brandx");            // the bundle's brand
        m.setCreatedAt(Instant.now());
        userModules.save(m).block();
    }

    private static String aliceX() { return brandX.mint("alice-x", List.of("user")); }
    private static String bobX()   { return brandX.mint("bob-x",   List.of("user")); }  // same brand, NOT owner
    private static String anyY()   { return brandY.mint("any-y",   List.of("user")); }  // foreign brand
    private static String adminX() { return brandX.mint("admin-x", List.of("admin")); }
    private static String superadmin() { return brandX.mint("root", List.of("superadmin")); }

    // ───────────────────────── GET /bundles/slug/{slug} ─────────────────────────

    @Test
    void slug_owner_getsOwnBundle_publicSafe_noVersionDirNorOwner() {
        web.get().uri("/api/federation/bundles/slug/" + SLUG)
                .header("Authorization", "Bearer " + aliceX())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].slug").isEqualTo(SLUG)
                .jsonPath("$[0].contentHash").isEqualTo(HASH)
                // public-safe: the internal locator + owner identity are NOT on the wire.
                .jsonPath("$[0].versionDir").doesNotExist()
                .jsonPath("$[0].ownerUserId").doesNotExist();
    }

    @Test
    void slug_foreignBrand_getsEmptyList_neverCrossTenantMetadata() {
        // CROSS-USER DENY (tenant): a brand-Y caller queries brand-X's slug -> EMPTY.
        byte[] body = web.get().uri("/api/federation/bundles/slug/" + SLUG)
                .header("Authorization", "Bearer " + anyY())
                .exchange()
                .expectStatus().isOk()
                .expectBody().returnResult().getResponseBody();
        assertEmptyJsonArray(body);
    }

    @Test
    void slug_sameBrandNonOwner_getsEmptyList_neverPeerMetadata() {
        // CROSS-OWNER DENY (same brand): bob-x is brand-X but NOT the owner -> EMPTY.
        byte[] body = web.get().uri("/api/federation/bundles/slug/" + SLUG)
                .header("Authorization", "Bearer " + bobX())
                .exchange()
                .expectStatus().isOk()
                .expectBody().returnResult().getResponseBody();
        assertEmptyJsonArray(body);
    }

    @Test
    void slug_admin_seesOwnBrandSlug_regardlessOfOwner() {
        web.get().uri("/api/federation/bundles/slug/" + SLUG)
                .header("Authorization", "Bearer " + adminX())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].slug").isEqualTo(SLUG);
    }

    // ───────────────────────── GET /bundles/{contentHash} ─────────────────────────

    @Test
    void hash_owner_getsBundle_publicSafe() {
        web.get().uri("/api/federation/bundles/" + HASH)
                .header("Authorization", "Bearer " + aliceX())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.contentHash").isEqualTo(HASH)
                .jsonPath("$.versionDir").doesNotExist()
                .jsonPath("$.ownerUserId").doesNotExist();
    }

    @Test
    void hash_foreignBrand_is404_neverCrossTenantPivot() {
        // CROSS-USER DENY (tenant): a brand-Y caller resolves brand-X's hash -> 404,
        // never the foreign row's metadata (and so no versionDir to pivot into bytes).
        String body = web.get().uri("/api/federation/bundles/" + HASH)
                .header("Authorization", "Bearer " + anyY())
                .exchange()
                .expectStatus().isNotFound()
                .expectBody(String.class).returnResult().getResponseBody();
        // mutation-resistant: even the error body must not echo the internal locator.
        if (body != null) {
            org.assertj.core.api.Assertions.assertThat(body).doesNotContain(VERSION_LOCATOR_MARKER);
        }
    }

    @Test
    void hash_sameBrandNonOwner_is404_neverPeerPivot() {
        // CROSS-OWNER DENY (same brand): bob-x is brand-X but not the owner -> 404.
        web.get().uri("/api/federation/bundles/" + HASH)
                .header("Authorization", "Bearer " + bobX())
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void hash_superadmin_resolvesAnyBrand() {
        web.get().uri("/api/federation/bundles/" + HASH)
                .header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.contentHash").isEqualTo(HASH);
    }

    // ───────────── byte FETCH stays any-authenticated (NOT weakened) ─────────────

    @Test
    void fetch_brandYToken_stillGets200_notWeakened() {
        // The capability-by-hash SYNC read is UNCHANGED by the metadata fix: a foreign
        // brand still streams the bytes. If the fix had wrongly added a cut here this
        // would 403/404 (change-detector for an over-tightening).
        web.get().uri("/api/federation/bundles/" + HASH + "/files/" + ENTRY)
                .header("Authorization", "Bearer " + anyY())
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo(BODY);
    }

    @Test
    void fetch_anonymous_is401_authenticatedFloorHolds() {
        web.get().uri("/api/federation/bundles/" + HASH + "/files/" + ENTRY)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private static void assertEmptyJsonArray(byte[] body) {
        String s = body == null ? "" : new String(body, StandardCharsets.UTF_8).trim();
        org.assertj.core.api.Assertions.assertThat(s)
                .as("a cross-tenant / cross-owner slug list must be empty")
                .isIn("[]", "");
        org.assertj.core.api.Assertions.assertThat(s).doesNotContain(VERSION_LOCATOR_MARKER);
        org.assertj.core.api.Assertions.assertThat(s).doesNotContain("alice-x");
    }
}
