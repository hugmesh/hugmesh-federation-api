package systems.snapdragon.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.federation.testsupport.TestIssuer;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end HTTP-boundary authz for the federation read + bundle surfaces, through
 * the REAL production filter chain in genuine MULTI-ISSUER (per-brand Casdoor) mode,
 * against the REAL R2DBC repositories + filesystem bundle storage. Sibling of
 * {@link ModerationDecideEscalationTest}; covers the manifest, module-registry,
 * override and bundle controllers.
 *
 * <p>Two per-brand {@link TestIssuer} servers ({@code brandx}, {@code brandy}) plus
 * an untrusted {@code rogue} issuer give the
 * {@link systems.snapdragon.commons.security.DomainRegistry} two trusted issuers
 * (so {@code isMultiIssuer()} holds and the per-issuer resolver swaps in) and an
 * unlisted one (for the fail-closed end-to-end case). A brand's token validates ONLY
 * against that brand's manager, so the per-request domain is the cryptographically
 * validated {@code iss} — never a param/body.
 *
 * <p>Coverage (comprehensive test standard categories):
 * <ul>
 *   <li><b>MANIFEST</b> — anon 401; an unknown-issuer token 401s at the DECODER
 *       (so PrincipalDomain is never reached); VISIBILITY cut (internal remote hidden
 *       from a plain user, shown to admin); DOMAIN cut (brand-X sees only brand-X
 *       remotes, never brand-Y).</li>
 *   <li><b>MODULE REGISTRY / OVERRIDE</b> — USER 403, anon 401, brand-X admin 404
 *       on a real brand-Y slug (cross-domain isolation), same-brand 200.</li>
 *   <li><b>BUNDLE (owner==subject)</b> — anon 401; a non-owner read/delete of
 *       another user's card is 404 (never the victim's bytes, never a cross-tenant
 *       delete); a cross-owner PUT to an occupied slug is 409 (the BOLA-fix
 *       regression), with the victim's active row left intact.</li>
 * </ul>
 *
 * <p>NO production code is changed.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class FederationHttpAuthzE2eTest extends PostgresTestSupport {

    private static final TestIssuer BRANDX = new TestIssuer();
    private static final TestIssuer BRANDY = new TestIssuer();
    private static final TestIssuer ROGUE  = new TestIssuer();   // well-formed but NOT trusted

    @DynamicPropertySource
    static void tenancy(DynamicPropertyRegistry reg) {
        // brandx + brandy trusted => multi-issuer; rogue deliberately left OUT of the
        // allowlist so a rogue token 401s at the per-issuer resolver. issuer-uri left
        // unset so the back-compat decoder path is never taken (both brands discover
        // from their own in-process OIDC server); the bogus application-test.yml
        // jwk-set-uri stays so Boot's lazy default decoder bean still builds.
        reg.add("app.tenancy.issuers",
                () -> BRANDX.issuerUri() + "=brandx," + BRANDY.issuerUri() + "=brandy");
        // DB wiring (r2dbc + liquibase) comes from PostgresTestSupport's @ServiceConnection
        // container — the H2 dual-URL lines were dropped.
    }

    @AfterAll
    static void stopIssuers() {
        BRANDX.close();
        BRANDY.close();
        ROGUE.close();
    }

    @Autowired WebTestClient web;
    @Autowired FederationModuleRepository modules;
    @Autowired UserModuleRepository userModules;

    @BeforeEach
    void clean() {
        // Drop only the rows this test seeds (the Liquibase seed modules stay) so the
        // domain/visibility assertions reason about exactly what we insert.
        userModules.deleteAll().block();
    }

    private String token(TestIssuer brand, String sub, List<String> roles) {
        return brand.mint(sub, roles);
    }

    private FederationModule seedModule(String slug, String domain, String visibility) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility(visibility);
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setDomain(domain);
        m.setCreatedAt(Instant.now());
        m.setUpdatedAt(Instant.now());
        return modules.save(m).block();
    }

    // ─────────────────────────── MANIFEST ───────────────────────────

    @Test
    void manifest_anonymous_is401() {
        web.get().uri("/api/federation/manifest").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void manifest_unknownIssuerToken_is401_atDecoder_beforeDomainScope() {
        // A perfectly valid, correctly-signed JWT — its iss is just NOT in
        // app.tenancy.issuers. The per-issuer resolver returns empty -> 401 at the
        // decoder, BEFORE the controller (and PrincipalDomain.resolve) runs. Fail-closed.
        web.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token(ROGUE, "attacker", List.of("admin", "superadmin")))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void manifest_visibilityCut_internalHiddenFromUser_shownToAdmin() {
        seedModule("brandx-public", "brandx", "public");
        seedModule("brandx-secret", "brandx", "internal");

        // a plain brand-X user sees the public remote but NOT the internal one
        FederationManifestDto asUser = web.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token(BRANDX, "u", List.of("user")))
                .exchange().expectStatus().isOk()
                .expectBody(FederationManifestDto.class).returnResult().getResponseBody();
        assertThat(slugs(asUser))
                .as("a plain user sees public remotes only")
                .contains("brandx-public")
                .doesNotContain("brandx-secret");

        // a brand-X admin (canSeeInternal) sees BOTH
        FederationManifestDto asAdmin = web.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token(BRANDX, "a", List.of("admin")))
                .exchange().expectStatus().isOk()
                .expectBody(FederationManifestDto.class).returnResult().getResponseBody();
        assertThat(slugs(asAdmin))
                .as("an admin additionally sees internal-visibility remotes")
                .contains("brandx-public", "brandx-secret");
    }

    @Test
    void manifest_domainCut_brandXNeverSeesBrandYRemotes() {
        seedModule("brandx-only", "brandx", "public");
        seedModule("brandy-only", "brandy", "public");

        FederationManifestDto asBrandX = web.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token(BRANDX, "u", List.of("admin")))
                .exchange().expectStatus().isOk()
                .expectBody(FederationManifestDto.class).returnResult().getResponseBody();
        assertThat(slugs(asBrandX))
                .as("the per-domain manifest is pinned to the caller's validated-issuer brand")
                .contains("brandx-only")
                .doesNotContain("brandy-only");

        FederationManifestDto asBrandY = web.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token(BRANDY, "u", List.of("admin")))
                .exchange().expectStatus().isOk()
                .expectBody(FederationManifestDto.class).returnResult().getResponseBody();
        assertThat(slugs(asBrandY))
                .contains("brandy-only")
                .doesNotContain("brandx-only");
    }

    // ──────────────────── MODULE REGISTRY / OVERRIDE ────────────────────

    @Test
    void modules_anonymous_is401() {
        web.get().uri("/api/federation/modules").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void modules_plainUser_is403() {
        web.get().uri("/api/federation/modules")
                .header("Authorization", "Bearer " + token(BRANDX, "u", List.of("user")))
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void overrides_plainUser_is403() {
        web.get().uri("/api/federation/overrides")
                .header("Authorization", "Bearer " + token(BRANDX, "u", List.of("user")))
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void getModule_brandXAdmin_seesOwnBrandSlug_200() {
        seedModule("x-mod", "brandx", "public");
        web.get().uri("/api/federation/modules/x-mod")
                .header("Authorization", "Bearer " + token(BRANDX, "a", List.of("admin")))
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.slug").isEqualTo("x-mod");
    }

    @Test
    void getModule_brandXAdmin_crossDomainSlug_is404_neverLeaksBrandYRow() {
        // A real, existing brand-Y module slug requested by a brand-X admin: the
        // domain-pinned finder (findBySlugAndDomain(slug,"brandx")) returns empty ->
        // 404. The brand-Y row is never surfaced cross-tenant.
        seedModule("y-mod", "brandy", "public");
        web.get().uri("/api/federation/modules/y-mod")
                .header("Authorization", "Bearer " + token(BRANDX, "a", List.of("admin")))
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void deleteModule_brandXAdmin_crossDomainSlug_is404_andBrandYRowSurvives() {
        seedModule("y-mod-del", "brandy", "public");
        web.delete().uri("/api/federation/modules/y-mod-del")
                .header("Authorization", "Bearer " + token(BRANDX, "a", List.of("admin")))
                .exchange().expectStatus().isNotFound();
        // the victim brand-Y row is still present (a cross-domain delete is a no-op)
        assertThat(modules.findBySlugAndDomain("y-mod-del", "brandy").block())
                .as("a cross-domain delete must never remove another brand's module")
                .isNotNull();
    }

    // ──────────────────── BUNDLE (owner == subject) ────────────────────

    @Test
    void bundle_anonymousList_is401() {
        web.get().uri("/api/federation/bundles/mine").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void bundle_anonymousDelete_is401() {
        web.delete().uri("/api/federation/bundles/card").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void bundle_ownerScoped_nonOwnerNeverReadsOrDeletesAnotherUsersCard() {
        // alice publishes a card (PUT goes through the real filesystem storage).
        putBundle("alice", "card", "<h1>alice</h1>").expectStatus().isOk();

        // alice can read her own body back
        web.get().uri("/api/federation/bundles/slug/card/body")
                .header("Authorization", "Bearer " + token(BRANDX, "alice", List.of("user")))
                .exchange().expectStatus().isOk();

        // bob (a different subject, same brand) reading alice's slug -> 404, NEVER
        // alice's bytes. owner == JWT subject is enforced in the service.
        web.get().uri("/api/federation/bundles/slug/card/body")
                .header("Authorization", "Bearer " + token(BRANDX, "bob", List.of("user")))
                .exchange().expectStatus().isNotFound();

        // bob deleting alice's slug -> 404 (never a cross-tenant delete)
        web.delete().uri("/api/federation/bundles/card")
                .header("Authorization", "Bearer " + token(BRANDX, "bob", List.of("user")))
                .exchange().expectStatus().isNotFound();

        // alice's active row is still there afterwards
        assertThat(userModules.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                "card", "alice").block())
                .as("a non-owner's read/delete leaves the owner's active card intact")
                .isNotNull();
    }

    @Test
    void bundle_crossOwnerPut_is409_andVictimRowUntouched() {
        // alice owns slug "shared"
        putBundle("alice", "shared", "<h1>alice</h1>").expectStatus().isOk();
        Long aliceRowId = userModules.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                "shared", "alice").block().getId();

        // bob (non-admin) PUTting the SAME slug must be 409 BEFORE any supersede — the
        // prior BOLA fix (cross-owner supersede). The victim's active row stays active.
        putBundle("bob", "shared", "<h1>bob takeover</h1>")
                .expectStatus().value(s -> assertThat(s).isEqualTo(409));

        var aliceRowAfter = userModules.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                "shared", "alice").block();
        assertThat(aliceRowAfter)
                .as("a cross-owner PUT must not displace the victim's active card")
                .isNotNull();
        assertThat(aliceRowAfter.getId())
                .as("the victim's same active row survives untouched")
                .isEqualTo(aliceRowId);
    }

    /** PUT a single-file bundle as the given owner (brand-X user). */
    private WebTestClient.ResponseSpec putBundle(String owner, String slug, String body) {
        return web.put().uri("/api/federation/bundles/" + slug)
                .header("Authorization", "Bearer " + token(BRANDX, owner, List.of("user")))
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .bodyValue(body.getBytes())
                .exchange();
    }

    private static List<String> slugs(FederationManifestDto m) {
        assertThat(m).isNotNull();
        return m.remotes().stream().map(FederationManifestDto.FederationRemoteDto::slug).toList();
    }
}
