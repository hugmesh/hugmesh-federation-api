package systems.hugmesh.federation.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import systems.hugmesh.commons.security.DomainRegistry;

/**
 * Shared scaffolding for the federation-api SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig#filterChain} (the actual {@code authorizeExchange} path
 * policy + the OAuth2 resource-server wiring), with NO full Spring Boot context.
 *
 * <p>COPIED (package + constructor adjusted) from the canonical
 * {@code systems.hugmesh.gateway.config.SecuritySliceSupport} — see
 * {@code docs/testing/MULTI-ISSUER-SLICE.md}. This repo's {@code SecurityConfig}
 * takes the SAME two constructor args as the gateway's
 * ({@code DomainRegistry} + the optional per-issuer resolver
 * {@code ObjectProvider}), so the constructor call here is unchanged. The ONLY
 * difference is which {@code @Bean} method builds the chain: this repo splits the
 * chain into a {@code @Profile("dev","test") devFilterChain} (spec paths permitAll)
 * and a {@code @Profile("!dev & !test") filterChain} (the PROD chain — spec paths
 * gated to ADMIN/SUPERADMIN). The route rules under test (vanity/capabilities
 * public, manifest authenticated, moderation MOD/ADMIN/SUPERADMIN, the
 * {@code anyExchange().authenticated()} floor) are IDENTICAL across both, so we
 * drive the PROD {@code filterChain} here (the stricter one).
 *
 * <p><b>Scope of the slice.</b> This builds only the {@code SecurityWebFilterChain}
 * (the coarse {@code authorizeExchange} path gate + the resource-server JWT
 * decoder). It does NOT activate {@code @EnableReactiveMethodSecurity}'s
 * {@code @PreAuthorize} method gates — those need the AOP proxy from a real
 * application context. The {@code decide} escalation boundary (a path-gate-passing
 * MOD that {@code @PreAuthorize} then DENIES) is therefore proven in a sibling
 * {@code @SpringBootTest} ({@code ModerationDecideEscalationTest}); the coarse
 * path-gate (anonymous 401, MOD reaches the moderation surface, role floors) lives
 * here.
 */
abstract class SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real {@link SecurityConfig#filterChain} built from a fresh
     * {@link ServerHttpSecurity}. The chain is installed as a {@link WebFilterChainProxy}
     * web filter so the resource-server authentication + the {@code authorizeExchange}
     * policy run exactly as in production.
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        // MFA floor ships DARK (enabled=false) — these route-gate slices assert the
        // legacy, byte-identical behaviour; the dark default emits no MFA_SATISFIED.
        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600_000L);
        // The PROD filter chain (spec paths -> ADMIN/SUPERADMIN). Every route rule the
        // slice exercises is shared with the dev/test chain, so the prod chain is the
        // stricter, representative one to assert against.
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                // FLAKE FIX (rank 17a): the multi-issuer path's FIRST touch of a given
                // brand lazily builds that brand's decoder via
                // ReactiveJwtDecoders.fromIssuerLocation(iss) — a SYNCHRONOUS OIDC
                // discovery (two sequential HTTP round-trips to the in-process
                // TestIssuer, whose JDK HttpServer runs on a single synchronous
                // executor). On a many-core dev box that cold first-touch is ~300ms;
                // on a 1-2 core CI runner (cold JVM + cold Netty WebClient bootstrap +
                // JUnit's NON-deterministic method ordering deciding which test eats the
                // cold start) it can exceed WebTestClient's DEFAULT 5s blocking-read
                // budget (DefaultWebTestClient: responseTimeout defaults to
                // Duration.ofSeconds(5)) — surfacing as the reported "~5s reactive
                // blocking-read timeout" flake (~2/3 of clean CI runs). Pinning an
                // EXPLICIT, generous budget makes the slice deterministic WITHOUT
                // touching any assertion: a tampered/unknown/cross-brand token still
                // runs the REAL decoder and still fail-closes 401; we only stop a slow
                // first-touch from being misread as a failure. Override via
                // -Dfederation.slice.responseTimeoutSeconds=<n> if a runner needs more.
                .configureClient()
                .responseTimeout(sliceResponseTimeout())
                .build();
    }

    /** The slice's WebTestClient blocking-read budget. Generous by default (30s) so a
     *  cold first-touch OIDC discovery on a constrained CI runner never trips the 5s
     *  default; overridable via {@code federation.slice.responseTimeoutSeconds}. This
     *  is purely a TEST-harness wait ceiling — it weakens NO security assertion. */
    private static java.time.Duration sliceResponseTimeout() {
        long secs = Long.getLong("federation.slice.responseTimeoutSeconds", 30L);
        if (secs < 5L) secs = 5L; // never go below the framework default
        return java.time.Duration.ofSeconds(secs);
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
