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
import systems.hugmesh.commons.config.TenancyResolvers;
import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.federation.testsupport.TestIssuer;

import java.util.List;

/**
 * Coarse PATH-GATE slice for the SUPERADMIN admin-modules surface
 * ({@code /api/federation/admin/modules/**}) — the {@link SecurityConfig}
 * {@code hasRole("SUPERADMIN")} rule end-to-end through the REAL production filter
 * chain with REAL RS256 tokens (in-process {@link TestIssuer}), in the
 * {@code SecurityConfigPathGateSliceTest} style.
 *
 * <p>The load-bearing assertion here is the NARROWNESS of the gate: unlike the
 * sibling {@code /api/federation/modules/**} rule
 * ({@code hasAnyRole("ADMIN","SUPERADMIN")}), this surface admits ONLY
 * ROLE_SUPERADMIN — a per-brand ADMIN (who freely reaches the general registry)
 * must be 403 on every verb, because the admin surface writes cross-brand
 * control-plane state. Nothing sits above SUPERADMIN in the role hierarchy, so
 * {@code hasRole("SUPERADMIN")} cannot be satisfied transitively.
 *
 * <p>Delineated:
 * <ul>
 *   <li><b>ANONYMOUS DENY</b> — 401 on GET/POST/DELETE with no credentials;</li>
 *   <li><b>CROSS-USER DENY (fail-closed issuer)</b> — a correctly-signed
 *       superadmin token from an issuer NOT in {@code app.tenancy.issuers} is 401
 *       at the decoder;</li>
 *   <li><b>USER-SITUATIONAL DENY</b> — ROLE_USER, ROLE_MOD and (critically)
 *       ROLE_ADMIN are 403 on every verb;</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — ROLE_SUPERADMIN passes the path gate on
 *       every verb (the method-level {@code @PreAuthorize} + service behaviour are
 *       proven in {@code AdminModuleServiceTest} / {@code AdminModuleEndpointTest};
 *       this slice asserts the coarse gate only, per the
 *       {@link SecuritySliceSupport} scope note).</li>
 * </ul>
 */
class AdminModulePathGateSliceTest extends SecuritySliceSupport {

    private static final String COLLECTION = "/api/federation/admin/modules";
    private static final String ITEM = "/api/federation/admin/modules/some-slug";

    private TestIssuer brandX;
    private TestIssuer brandY;   // second trusted issuer so isMultiIssuer() holds
    private TestIssuer rogue;    // NOT trusted — the fail-closed end-to-end case
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

    private String token(List<String> roles) {
        return brandX.mint("p-" + String.join("-", roles), roles);
    }

    // ── ANONYMOUS DENY — every verb 401s with no credentials ──────────────────

    @Test
    void anonymous_deniedOn_list() {
        client.get().uri(COLLECTION).exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_upsert() {
        client.post().uri(COLLECTION).exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_softDisable() {
        client.delete().uri(ITEM).exchange().expectStatus().isUnauthorized();
    }

    // ── CROSS-USER DENY — unknown-issuer superadmin token fail-closes 401 ─────

    @Test
    void unknownIssuerSuperadminToken_is401_onEveryVerb() {
        // Correctly signed + carries superadmin — but the iss is untrusted, so the
        // per-issuer resolver yields empty => 401 at the DECODER, before any gate.
        String forged = rogue.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri(COLLECTION).header("Authorization", "Bearer " + forged)
                .exchange().expectStatus().isUnauthorized();
        client.post().uri(COLLECTION).header("Authorization", "Bearer " + forged)
                .exchange().expectStatus().isUnauthorized();
        client.delete().uri(ITEM).header("Authorization", "Bearer " + forged)
                .exchange().expectStatus().isUnauthorized();
    }

    // ── USER-SITUATIONAL DENY — every role below SUPERADMIN is 403 ────────────

    @Test
    void user_forbiddenOn_everyVerb() {
        String user = token(List.of("user"));
        client.get().uri(COLLECTION).header("Authorization", "Bearer " + user)
                .exchange().expectStatus().isForbidden();
        client.post().uri(COLLECTION).header("Authorization", "Bearer " + user)
                .exchange().expectStatus().isForbidden();
        client.delete().uri(ITEM).header("Authorization", "Bearer " + user)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void mod_forbiddenOn_list() {
        client.get().uri(COLLECTION).header("Authorization", "Bearer " + token(List.of("mod")))
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void admin_forbiddenOn_everyVerb_gateIsExactlySuperadmin() {
        // THE load-bearing narrowness proof: a per-brand ADMIN — who freely reaches
        // /api/federation/modules/** — is DENIED the cross-brand admin surface on
        // every verb. If the rule ever widened to hasAnyRole("ADMIN","SUPERADMIN")
        // (a copy-paste from the sibling rule), these three assertions fail.
        String admin = token(List.of("admin"));
        client.get().uri(COLLECTION).header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isForbidden();
        client.post().uri(COLLECTION).header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isForbidden();
        client.delete().uri(ITEM).header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isForbidden();
    }

    // ── USER-SITUATIONAL ALLOW — SUPERADMIN passes the path gate ──────────────

    @Test
    void superadmin_allowedOn_everyVerb() {
        String superadmin = token(List.of("superadmin"));
        client.get().uri(COLLECTION).header("Authorization", "Bearer " + superadmin)
                .exchange().expectStatus().isOk();
        client.post().uri(COLLECTION).header("Authorization", "Bearer " + superadmin)
                .exchange().expectStatus().isOk();
        client.delete().uri(ITEM).header("Authorization", "Bearer " + superadmin)
                .exchange().expectStatus().isOk();
    }

    /** Maps the two admin-modules paths so an ALLOWED request resolves 200 (a 404
     *  would mask a missing security decision) — the path policy is
     *  controller-agnostic, so a flat probe is the right unit to assert it. */
    @RestController
    static class ProbeController {
        @RequestMapping({COLLECTION, ITEM})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
