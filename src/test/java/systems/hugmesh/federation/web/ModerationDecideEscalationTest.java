package systems.hugmesh.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.federation.model.ModerationRequest;
import systems.hugmesh.federation.repository.ModerationRequestRepository;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.federation.testsupport.TestIssuer;

import java.time.Instant;
import java.util.List;

/**
 * HTTP-boundary authz for the moderation {@code decide} escalation + the
 * CROSS-DOMAIN DENY, end-to-end through the REAL production filter chain in genuine
 * MULTI-ISSUER (per-brand Casdoor) mode, against the REAL R2DBC repositories.
 *
 * <p>This is the {@code ModerationDecideEscalationTest} the multi-issuer slice
 * docs/tests (PR #25) explicitly DEFER to a sibling {@code @SpringBootTest}: the
 * fast coarse-path slice can only prove the {@code authorizeExchange} gate (MOD
 * reaches the {@code /moderation/**} surface); it canNOT prove the
 * {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")} narrowing on
 * {@code POST /{id}/decide}, because {@code @EnableReactiveMethodSecurity}'s AOP
 * proxy needs a real application context. We supply exactly that here.
 *
 * <p>Two real per-brand {@link TestIssuer} servers ({@code brandx}, {@code brandy})
 * give the {@link systems.hugmesh.commons.security.DomainRegistry} two trusted
 * issuers, so {@code isMultiIssuer()} holds and {@code SecurityConfig} swaps onto the
 * per-issuer resolver. A brand-X token validates ONLY against brand-X's manager and
 * resolves (via the cryptographically-validated {@code iss}) to {@code DOMAIN_brandx}
 * — the domain is NEVER taken from a request param or body.
 *
 * <p>Categories asserted (comprehensive test standard):
 * <ul>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — a brand-X ADMIN decides a brand-X request
 *       (200 + status flips), proving the privileged role reaches the surface.</li>
 *   <li><b>CROSS-USER ROLE DENY (escalation)</b> — a brand-X MOD is 403 on
 *       {@code decide} (method security narrows it past the coarse MOD path-gate),
 *       and the row is left UNDECIDED — a mod can never approve/deny.</li>
 *   <li><b>CROSS-USER DOMAIN DENY (tenant isolation)</b> — a brand-Y ADMIN deciding
 *       a brand-X request id is 404 (the domain-pinned finder returns empty), and the
 *       victim brand-X row stays UNDECIDED. The id is real; only the brand differs —
 *       so this proves the cut is keyed off the validated issuer, not the path.</li>
 *   <li><b>ANONYMOUS DENY</b> — {@code decide} with no token is 401.</li>
 * </ul>
 *
 * <p>NO production code is changed; the test merely drives the existing chain.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ModerationDecideEscalationTest extends PostgresTestSupport {

    // Two trusted brands + one untrusted rogue, started ONCE for the context.
    private static final TestIssuer BRANDX = new TestIssuer();
    private static final TestIssuer BRANDY = new TestIssuer();

    @DynamicPropertySource
    static void tenancy(DynamicPropertyRegistry reg) {
        // Two trusted issuers => isMultiIssuer() => SecurityConfig takes the
        // per-issuer resolver swap. Each brand's decoder is built LAZILY from its OWN
        // OIDC discovery doc (the in-process TestIssuer).
        //
        // We deliberately DO NOT set spring.security.oauth2.resourceserver.jwt.issuer-uri
        // (so TenancyResourceServerConfig's backCompatIssuer stays empty and
        // decoderForIssuer takes the fromIssuerLocation discovery path for BOTH brands,
        // never the back-compat withJwkSetUri path). We also leave the bogus back-compat
        // jwk-set-uri from application-test.yml (http://localhost:0/jwks) in place: Boot's
        // ReactiveOAuth2ResourceServerJwkConfiguration needs it to build its (lazy, never
        // dialled) default jwtDecoder bean, and SecurityConfig ignores that bean entirely
        // once it swaps onto the multi-issuer resolver.
        reg.add("app.tenancy.issuers",
                () -> BRANDX.issuerUri() + "=brandx," + BRANDY.issuerUri() + "=brandy");
        // DB wiring (r2dbc + liquibase) comes from PostgresTestSupport's @ServiceConnection
        // container; this @SpringBootTest context gets its own isolated PG.
    }

    @AfterAll
    static void stopIssuers() {
        BRANDX.close();
        BRANDY.close();
    }

    @Autowired WebTestClient web;
    @Autowired ModerationRequestRepository requests;

    /** Seed a {@code recommended} request stamped with the given brand, return its id. */
    private Long seedRequest(String domain) {
        ModerationRequest r = new ModerationRequest();
        r.setRequester("seed");
        r.setKind("instance-block");
        r.setTarget("evil.example");
        r.setReason("spam");
        r.setStatus("recommended");
        r.setDomain(domain);
        r.setTs(Instant.now());
        return requests.save(r).map(ModerationRequest::getId).block();
    }

    private String statusOf(Long id) {
        return requests.findById(id).map(ModerationRequest::getStatus).block();
    }

    private WebTestClient.RequestHeadersSpec<?> bearerPost(TestIssuer brand, String sub,
                                                           List<String> roles, String uri) {
        return web.post().uri(uri).header("Authorization", "Bearer " + brand.mint(sub, roles));
    }

    @BeforeEach
    void clean() {
        requests.deleteAll().block();
    }

    // ── USER-SITUATIONAL ALLOW: a brand-X ADMIN decides a brand-X request ──────

    @Test
    void brandXAdmin_decidesBrandXRequest_200_andStatusFlips() {
        Long id = seedRequest("brandx");
        bearerPost(BRANDX, "admin-x", List.of("admin"),
                "/api/federation/moderation/" + id + "/decide?approve=true")
                .exchange()
                .expectStatus().isOk();
        org.assertj.core.api.Assertions.assertThat(statusOf(id))
                .as("an authorized same-brand admin decision flips the row to approved")
                .isEqualTo("approved");
    }

    @Test
    void brandXSuperadmin_decidesBrandXRequest_200() {
        Long id = seedRequest("brandx");
        bearerPost(BRANDX, "su", List.of("superadmin"),
                "/api/federation/moderation/" + id + "/decide?approve=false")
                .exchange()
                .expectStatus().isOk();
        org.assertj.core.api.Assertions.assertThat(statusOf(id)).isEqualTo("denied");
    }

    // ── CROSS-USER ROLE DENY: a MOD cannot decide (method-security escalation) ──

    @Test
    void brandXMod_decide_is403_byMethodSecurity_andRowStaysUndecided() {
        Long id = seedRequest("brandx");
        // The coarse path gate ADMITS a MOD on /moderation/** — only @PreAuthorize on
        // decide() (ADMIN/SUPERADMIN) rejects this. So a 403 here proves the method
        // gate fires, not the path gate.
        bearerPost(BRANDX, "mod-x", List.of("mod"),
                "/api/federation/moderation/" + id + "/decide?approve=true")
                .exchange()
                .expectStatus().isForbidden();
        org.assertj.core.api.Assertions.assertThat(statusOf(id))
                .as("a mod's denied decide must NOT mutate the request")
                .isEqualTo("recommended");
    }

    @Test
    void brandXMod_canStillReferAndList_butNotDecide() {
        // Sanity: the same MOD that is 403 on decide is allowed to refer (proving the
        // 403 is the decide-specific narrowing, not a blanket moderation denial).
        Long id = seedRequest("brandx");
        bearerPost(BRANDX, "mod-x", List.of("mod"),
                "/api/federation/moderation/" + id + "/refer")
                .exchange()
                .expectStatus().isOk();
        org.assertj.core.api.Assertions.assertThat(statusOf(id)).isEqualTo("referred");
    }

    // ── CROSS-USER DOMAIN DENY: a brand-Y admin cannot decide a brand-X request ──

    @Test
    void brandYAdmin_decidingBrandXRequest_is404_andBrandXRowUntouched() {
        Long id = seedRequest("brandx");
        // brand-Y admin presents a brand-Y-issued token (validated iss => DOMAIN_brandy)
        // and targets a real brand-X id. The domain-pinned finder
        // (findByIdAndDomain(id,"brandy")) returns empty => 404. The cross-domain row is
        // never surfaced, never decided. This proves the brand is the VALIDATED ISSUER,
        // never the path/param.
        bearerPost(BRANDY, "admin-y", List.of("admin"),
                "/api/federation/moderation/" + id + "/decide?approve=true")
                .exchange()
                .expectStatus().isNotFound();
        org.assertj.core.api.Assertions.assertThat(statusOf(id))
                .as("a cross-brand admin can never decide another brand's request")
                .isEqualTo("recommended");
    }

    @Test
    void brandYMod_referringBrandXRequest_is404_crossDomainIsolation() {
        Long id = seedRequest("brandx");
        bearerPost(BRANDY, "mod-y", List.of("mod"),
                "/api/federation/moderation/" + id + "/refer")
                .exchange()
                .expectStatus().isNotFound();
        org.assertj.core.api.Assertions.assertThat(statusOf(id)).isEqualTo("recommended");
    }

    // ── ANONYMOUS DENY ─────────────────────────────────────────────────────────

    @Test
    void anonymous_decide_is401() {
        Long id = seedRequest("brandx");
        web.post().uri("/api/federation/moderation/" + id + "/decide?approve=true")
                .exchange()
                .expectStatus().isUnauthorized();
        org.assertj.core.api.Assertions.assertThat(statusOf(id)).isEqualTo("recommended");
    }
}
