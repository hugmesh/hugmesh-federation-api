package systems.hugmesh.federation.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.config.TenancyResolvers;
import systems.hugmesh.federation.testsupport.TestIssuer;

import java.util.List;

/**
 * KEYSTONE coarse PATH-GATE slice — the {@link SecurityConfig}
 * {@code authorizeExchange} policy, end-to-end through the REAL filter chain
 * (mirrors the gateway {@code SecurityConfigPathGateSliceTest}). The existing
 * {@code DomainAuthzEndpointTest} proves the privileged-list AUTHZ with a full
 * {@code @SpringBootTest}; this fast slice locks down the rest of the path table —
 * the PUBLIC permitAll rules, the {@code authenticated()} floor, and the
 * fail-closed posture of an UNKNOWN-issuer token end-to-end.
 *
 * <p>Drives tokens through the multi-issuer resolver path (the only no-network
 * decoder seam — backed by an in-process {@link TestIssuer}); the
 * {@code authorizeExchange} rules under test are identical on the single-issuer
 * path. A {@code rogue} (untrusted) issuer covers the fail-closed end-to-end case.
 *
 * <p>Asserts:
 * <ul>
 *   <li><b>ANONYMOUS DENY</b> — {@code GET /api/federation/manifest} (the
 *       {@link systems.hugmesh.federation.controller.FederationController}
 *       surface) and an arbitrary gated path 401 anonymous (the
 *       {@code anyExchange().authenticated()} floor + the explicit manifest rule);</li>
 *   <li><b>UNKNOWN-ISSUER FAIL-CLOSED END-TO-END</b> — a well-formed, correctly
 *       signed token from an issuer NOT in {@code app.tenancy.issuers}, presented to
 *       {@code /api/federation/manifest}, 401s at the DECODER — so
 *       {@code PrincipalDomain.resolve(...)} is NEVER reached for an untrusted tenant;</li>
 *   <li><b>USER-SITUATIONAL DENY</b> — {@code ROLE_USER} is 403 on the privileged
 *       paths (modules / overrides / username oracle), and even on the moderation
 *       surface (which floors at MOD);</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — {@code ROLE_MOD} reaches the moderation
 *       surface (coarse path gate — the {@code decide} narrowing to ADMIN is method
 *       security, proven in {@code ModerationDecideEscalationTest});
 *       {@code ROLE_ADMIN} reaches modules / overrides;</li>
 *   <li><b>ANONYMOUS ALLOW</b> — the PUBLIC projections
 *       ({@code GET /api/federation/capabilities}, vanity resolve) are reachable
 *       with NO credentials.</li>
 * </ul>
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

    private TestIssuer brandX;
    private TestIssuer brandY;   // a second trusted issuer so isMultiIssuer() holds
    private TestIssuer rogue;    // NOT trusted — drives the fail-closed end-to-end case
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600_000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    private WebTestClient.RequestHeadersSpec<?> as(List<String> roles, String path) {
        String token = brandX.mint("p-" + String.join("-", roles), roles);
        return client.get().uri(path).header("Authorization", "Bearer " + token);
    }

    // ── ANONYMOUS DENY — the manifest surface + the authenticated() floor ──────

    @Test
    void anonymous_deniedOn_manifest() {
        // FederationController GET /manifest is `authenticated` — anonymous 401.
        client.get().uri("/api/federation/manifest").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_arbitraryGatedPath() {
        // anyExchange().authenticated() — an ungoverned, non-public path 401s anonymous.
        client.get().uri("/api/federation/bundles/some-bundle").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_vanityPublish_writeMethods() {
        // The vanity path rule (commonRoutes) is scoped to HttpMethod.GET ONLY —
        // PUT (publish) and DELETE (unpublish) on the SAME path fall through to the
        // anyExchange().authenticated() floor, so an anonymous caller can never
        // publish/unpublish a vanity profile even though the GET resolve is public.
        client.put().uri("/api/federation/vanity/alice").exchange().expectStatus().isUnauthorized();
        client.delete().uri("/api/federation/vanity/alice").exchange().expectStatus().isUnauthorized();
    }

    // ── UNKNOWN-ISSUER FAIL-CLOSED END-TO-END (PrincipalDomain never reached) ──────

    @Test
    void crossUser_unknownIssuerToken_onManifest_is401_beforeDomainScope() {
        // The rogue issuer mints a well-formed, correctly-signed JWT carrying admin +
        // a forged domain — but its `iss` is NOT in app.tenancy.issuers. The per-issuer
        // resolver returns Mono.empty() -> 401 at the DECODER, BEFORE the controller (and
        // thus before PrincipalDomain.resolve) ever runs. This is the end-to-end proof that
        // an untrusted tenant can never reach the domain-scoped query layer.
        String token = rogue.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_unknownIssuerToken_onModeration_is401() {
        String token = rogue.mint("attacker", List.of("mod"));
        client.get().uri("/api/federation/moderation")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── USER-SITUATIONAL DENY — ROLE_USER vs the privileged surfaces ──────────

    @Test
    void user_forbiddenOn_modules() {
        as(List.of("user"), "/api/federation/modules").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_forbiddenOn_overrides() {
        as(List.of("user"), "/api/federation/overrides").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_forbiddenOn_usernameOracle() {
        // The username availability oracle is SERVICE/ADMIN/SUPERADMIN — never a user.
        as(List.of("user"), "/api/federation/username/alice/availability")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void user_forbiddenOn_moderation() {
        // The moderation surface floors at MOD — a plain user never reaches it.
        as(List.of("user"), "/api/federation/moderation").exchange().expectStatus().isForbidden();
    }

    // ── USER-SITUATIONAL ALLOW — privileged roles reach their surfaces ─────────

    @Test
    void mod_allowedOn_moderationSurface() {
        // The COARSE path gate admits MOD on /api/federation/moderation/**. (The
        // decide endpoint's narrowing to ADMIN/SUPERADMIN is @PreAuthorize method
        // security — see ModerationDecideEscalationTest — not this path rule.)
        as(List.of("mod"), "/api/federation/moderation").exchange().expectStatus().isOk();
    }

    // ── recommend-instance-block: the narrower MATRIX/MASTODON self-service path ──
    // (root-cause fix: user-bff-api's POST /bff/user/recommend-instance-block used
    // to forward a plain user's own JWT to the MOD-only submit surface above, which
    // no RoleHierarchy edge could ever admit — see SecurityConfig's javadoc.)

    private WebTestClient.RequestHeadersSpec<?> postAs(List<String> roles, String path) {
        String token = brandX.mint("p-" + String.join("-", roles), roles);
        return client.post().uri(path).header("Authorization", "Bearer " + token);
    }

    @Test
    void matrix_allowedOn_recommendInstanceBlock() {
        postAs(List.of("matrix"), "/api/federation/moderation/recommend-instance-block")
                .exchange().expectStatus().isOk();
    }

    @Test
    void mastodon_allowedOn_recommendInstanceBlock() {
        postAs(List.of("mastodon"), "/api/federation/moderation/recommend-instance-block")
                .exchange().expectStatus().isOk();
    }

    @Test
    void user_forbiddenOn_recommendInstanceBlock() {
        // A plain user (no platform role) never reaches even this narrower surface.
        postAs(List.of("user"), "/api/federation/moderation/recommend-instance-block")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void mod_forbiddenOn_recommendInstanceBlock_gateIsExactlyMatrixMastodon() {
        // FAIL-CLOSED: proves the new path rule is EXACTLY ROLE_MATRIX/MASTODON, no
        // wider — a MOD (who freely reaches the general /moderation/** surface) does
        // NOT get an extra route in via this narrower one. Staff use POST / instead.
        postAs(List.of("mod"), "/api/federation/moderation/recommend-instance-block")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void anonymous_forbiddenOn_recommendInstanceBlock() {
        client.post().uri("/api/federation/moderation/recommend-instance-block")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    void admin_allowedOn_modules() {
        as(List.of("admin"), "/api/federation/modules").exchange().expectStatus().isOk();
    }

    @Test
    void admin_allowedOn_overrides() {
        as(List.of("admin"), "/api/federation/overrides").exchange().expectStatus().isOk();
    }

    @Test
    void superadmin_allowedOn_usernameOracle() {
        as(List.of("superadmin"), "/api/federation/username/alice/availability")
                .exchange().expectStatus().isOk();
    }

    @Test
    void authenticatedUser_allowedOn_manifest() {
        // Any validated principal (even a plain user) passes the manifest gate
        // (authenticated) — the visibility/DOMAIN cut happens in-code in ManifestService.
        as(List.of("user"), "/api/federation/manifest").exchange().expectStatus().isOk();
    }

    // ── ANONYMOUS ALLOW — the PUBLIC projections ──────────────────────────────

    @Test
    void anonymous_allowedOn_capabilities() {
        // Capabilities is a PUBLIC install-state projection — reachable with NO token.
        client.get().uri("/api/federation/capabilities").exchange()
                .expectStatus().value(s -> assertNot401Nor403("/api/federation/capabilities", s));
    }

    @Test
    void anonymous_allowedOn_vanityResolve() {
        // Vanity resolve is the PUBLIC profile served at <username>.<domain> — GET-only,
        // reachable anonymous.
        for (String path : List.of("/api/federation/vanity", "/api/federation/vanity/alice")) {
            client.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    /** A path reached by an ALLOWED (permitAll) request must not be 401/403. The
     *  probe controller maps every path below, so a permitAll path resolves to 200;
     *  the only failures we guard against are the security 401/403. */
    private static void assertNot401Nor403(String path, int status) {
        if (status == 401 || status == 403) {
            throw new AssertionError("expected anonymous ALLOW on " + path + " but got " + status);
        }
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200
     *  (instead of a 404 that could mask a missing security decision). The path
     *  policy is controller-agnostic, so a flat probe is the right unit to assert it. */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/api/federation/manifest",
                "/api/federation/capabilities",
                "/api/federation/vanity", "/api/federation/vanity/alice",
                "/api/federation/modules", "/api/federation/overrides",
                "/api/federation/moderation",
                "/api/federation/moderation/recommend-instance-block",
                "/api/federation/username/alice/availability",
                "/api/federation/bundles/some-bundle",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
