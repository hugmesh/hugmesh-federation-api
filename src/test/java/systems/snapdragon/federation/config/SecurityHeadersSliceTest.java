package systems.snapdragon.federation.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.security.DomainRegistry;
import systems.snapdragon.federation.testsupport.TestIssuer;

import java.util.List;

/**
 * HEADER-HARDENING slice — asserts the {@link SecurityConfig#applyHardenedHeaders}
 * block lands on responses that flow through the REAL
 * {@link SecurityConfig#filterChain}, AND that the additive header change did NOT
 * weaken the fail-closed authz posture.
 *
 * <p>This service is a per-domain, pure-JSON OAuth2 resource server BEHIND the
 * shared gateway, so the hardened set is the API-defensive MINIMUM (no HSTS, no
 * Permissions-Policy — those live at the TLS front door). We assert:
 * <ul>
 *   <li><b>added header present</b> — {@code Content-Security-Policy:
 *       default-src 'none'; frame-ancestors 'none'} on BOTH a PUBLIC (anonymous,
 *       200) response and an AUTHENTICATED (200) response;</li>
 *   <li><b>Spring secure DEFAULTS kept</b> — {@code X-Content-Type-Options: nosniff},
 *       {@code X-Frame-Options: DENY}, {@code Cache-Control: no-store} (proving the
 *       {@code .headers(...)} block did not disable the defaults);</li>
 *   <li><b>NO HSTS / NO Permissions-Policy on the BFF</b> — confirms the front-door
 *       headers were NOT misapplied to an intra-mesh resource server;</li>
 *   <li><b>authz UNCHANGED</b> — an anonymous request to an {@code authenticated()}
 *       path still 401s (the header change is behaviour-preserving), and a 401
 *       response STILL carries the hardened CSP (headers apply to error responses
 *       too).</li>
 * </ul>
 *
 * <p>Driven through the multi-issuer resolver seam (the only no-network decoder),
 * exactly as {@link SecurityConfigPathGateSliceTest}; the {@code .headers(...)}
 * block is identical on the single-issuer path.
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

    private static final String EXPECTED_CSP = "default-src 'none'; frame-ancestors 'none'";

    private TestIssuer brandX;
    private TestIssuer brandY; // a second trusted issuer so isMultiIssuer() holds
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy =
                new TenancyResourceServerConfig(registry, "", "", false, 600_000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenancy.tenantAuthManagerResolver();
        client = sliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
    }

    // ── added header present on a PUBLIC (anonymous) 200 ──────────────────────

    @Test
    void publicResponse_carriesHardenedCsp_andKeepsSpringDefaults() {
        client.get().uri("/api/federation/capabilities")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Content-Security-Policy", EXPECTED_CSP)
                // Spring reactive secure defaults — KEPT, never disabled.
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().valueEquals("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                // BFF must NOT emit front-door-only headers (HSTS over plaintext
                // intra-mesh is misleading; Permissions-Policy needs a doc surface).
                .expectHeader().doesNotExist("Strict-Transport-Security")
                .expectHeader().doesNotExist("Permissions-Policy");
    }

    // ── added header present on an AUTHENTICATED 200 ──────────────────────────

    @Test
    void authenticatedResponse_carriesHardenedCsp() {
        String token = brandX.mint("p-user", List.of("user"));
        client.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Content-Security-Policy", EXPECTED_CSP)
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY");
    }

    // ── authz UNCHANGED — anonymous on an authenticated() path still 401s ─────

    @Test
    void anonymous_on_authenticatedPath_still401s_withHardenedCsp() {
        // Header hardening is ADDITIVE — the fail-closed authz floor is untouched, and
        // the hardened CSP rides even the 401 error response.
        client.get().uri("/api/federation/manifest")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals("Content-Security-Policy", EXPECTED_CSP)
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff");
    }

    /** Minimal probe mapping the two paths this slice drives so an ALLOWED request
     *  resolves to 200 rather than a 404 that could mask a missing header decision. */
    @RestController
    static class ProbeController {
        @GetMapping({"/api/federation/manifest", "/api/federation/capabilities"})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
