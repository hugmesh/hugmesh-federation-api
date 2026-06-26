package systems.snapdragon.federation.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import systems.snapdragon.commons.config.TenancyResourceServerConfig;
import systems.snapdragon.commons.security.CasdoorAuthorities;
import systems.snapdragon.commons.security.DomainRegistry;

/**
 * Casdoor-aware OAuth2 resource-server security for snapdragon-federation-api
 * (reactive WebFlux). {@code @EnableReactiveMethodSecurity} activates the
 * {@code @PreAuthorize("hasRole('ADMIN')")} gates on the registry / override /
 * moderation controllers.
 *
 * <p>The JWT->authority mapping ({@link #casdoorAuthoritiesConverter}) delegates to
 * the canonical {@link CasdoorAuthorities} (copied from snapdragon-gateway): the
 * Casdoor {@code roles} claim (string or {@code {name}} objects) -&gt;
 * {@code ROLE_<UPPER>}; {@code permissions} verbatim EXCEPT reserved-prefix
 * ({@code ROLE_}/{@code DOMAIN_}) entries which are STRIPPED (authority-injection
 * defense); legacy {@code isAdmin} -&gt; {@code ROLE_ADMIN}; a {@code ROLE_USER}
 * floor; plus exactly ONE issuer-derived {@code DOMAIN_<x>} authority (NON-role;
 * {@code DOMAIN_default} for the single-issuer fallback so this cluster is
 * unchanged).
 *
 * <p><b>Multi-issuer is OPT-IN and backward-compatible.</b> The resource server
 * stays on the existing single {@code o.jwt(...)} issuer-uri wiring unless BOTH a
 * per-issuer resolver was contributed ({@link TenancyResourceServerConfig}, gated
 * on {@code app.tenancy.issuers} carrying {@code =} pairs) AND the registry is
 * genuinely multi-issuer ({@link DomainRegistry#isMultiIssuer()}). A single-issuer
 * cluster is byte-for-byte unchanged.
 *
 * <p>Gating:
 * <ul>
 *   <li>vanity resolve ({@code GET /api/federation/vanity/**}) = permitAll
 *       (PUBLIC — the public profile served at {@code <username>.<domain>});</li>
 *   <li>capabilities ({@code GET /api/federation/capabilities}) = permitAll
 *       (PUBLIC install-state projection — UNCHANGED);</li>
 *   <li>manifest read ({@code GET /api/federation/manifest}) = authenticated
 *       (visibility/role/DOMAIN-filtered in code by ManifestService);</li>
 *   <li>username availability ({@code /api/federation/username/**}) =
 *       ROLE_SERVICE/ADMIN/SUPERADMIN (INTERNAL enumeration oracle);</li>
 *   <li>module-write ({@code /api/federation/modules/**}), overrides
 *       ({@code /api/federation/overrides/**}) = ROLE_ADMIN or ROLE_SUPERADMIN;</li>
 *   <li>moderation ({@code /api/federation/moderation/**}) = ROLE_MOD/ADMIN/SUPERADMIN
 *       (method-security narrows decide to ROLE_ADMIN/SUPERADMIN);</li>
 *   <li>bundles ({@code /api/federation/bundles/**}) = authenticated
 *       (owner-or-admin enforced in the service: owner = JWT subject — UNWEAKENED;
 *       the metadata reads are additionally DOMAIN-scoped + projected to a public-safe
 *       view, while the content-hash byte FETCH stays any-authenticated by design);</li>
 *   <li>springdoc spec/UI = permitAll under dev/test, ROLE_ADMIN/SUPERADMIN in prod.</li>
 * </ul>
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /** Issuer-&gt;domain source of truth. Injected so the converter can stamp the
     *  cryptographically-validated {@code iss} as a {@code DOMAIN_<x>} authority.
     *  Single-issuer clusters get a registry that maps the lone issuer (or no
     *  issuer at all) to {@code DOMAIN_default}, so behaviour is unchanged. */
    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver. Present (non-null provider value)
     *  ONLY when {@code app.tenancy.issuers} is configured, via
     *  {@link TenancyResourceServerConfig}. When absent the resource server stays on
     *  the single {@code o.jwt(...)} issuer-uri wiring — byte-for-byte the current
     *  single-issuer path. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** D8 MFA floor — ships DARK. {@code app.mfa.enabled} (default {@code false}):
     *  when off the converter emits the byte-identical legacy authority set and the
     *  {@code MFA_SATISFIED} marker is NEVER produced. Threaded into the SAME
     *  {@link CasdoorAuthorities.MfaConfig} the multi-issuer path uses so both
     *  derive the marker identically. */
    private final boolean mfaEnabled;

    /** D8 MFA freshness window in millis ({@code app.mfa.freshness-window}, default
     *  10m): a {@code mfa_satisfied_at} stamp is fresh iff {@code 0 <= now - ts <=}
     *  this. */
    private final long mfaFreshnessWindow;

    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindow) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindow = mfaFreshnessWindow;
    }

    /**
     * Hardened reactive HTTP response headers (OWASP secure-headers / NIST 800-228 /
     * ASVS V14.4) applied to EVERY {@link SecurityWebFilterChain} here. This service
     * is a per-domain, pure-JSON OAuth2 <b>resource server</b> sitting BEHIND the
     * shared snapdragon-gateway front door — NOT the TLS-terminating gateway — so it
     * gets the API-defensive MINIMUM only:
     * <ul>
     *   <li>{@code Content-Security-Policy: default-src 'none'; frame-ancestors 'none'}
     *       — a no-document CSP (this API never serves HTML); defence-in-depth.</li>
     *   <li>Spring Security's reactive SECURE DEFAULTS are KEPT (not disabled):
     *       {@code X-Content-Type-Options: nosniff}, {@code X-Frame-Options: DENY},
     *       {@code Cache-Control: no-store}, {@code Referrer-Policy: no-referrer}.</li>
     * </ul>
     * Deliberately OMITTED on a BFF: {@code Strict-Transport-Security} (meaningless
     * over the plaintext intra-mesh hop; emitted ONLY at the TLS front door) and
     * {@code Permissions-Policy} (no browser document surface). Those belong on the
     * snapdragon-gateway chain, not here. Additive only — no authz / issuer / CSRF
     * posture is touched.
     */
    private static void applyHardenedHeaders(ServerHttpSecurity.HeaderSpec h) {
        h.contentSecurityPolicy(csp -> csp.policyDirectives(
                "default-src 'none'; frame-ancestors 'none'"));
        // nosniff + X-Frame-Options DENY + Cache-Control + Referrer-Policy:no-referrer
        // remain Spring Security reactive defaults — left implicit, never disabled.
    }

    /**
     * Shared route rules common to BOTH profiles. The ONLY per-profile difference is
     * how {@link #SPEC_PATHS} is gated, so every other route lives here to keep the
     * two chains in lockstep (mirrors admin-bff).
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // Vanity resolve is a PUBLIC read (the public profile served at
        // <username>.<domain>) — anonymous browsers hit it, so NO JWT is required.
        // Safe because VanityService ONLY ever returns a visibility='public',
        // enabled, circuit-closed profile fragment (filtered in the query + in
        // code); an internal / disabled / missing one is 404. GET-only so it can
        // never mutate. Declared BEFORE the authenticated catch-alls.
        ex.pathMatchers(HttpMethod.GET, "/api/federation/vanity", "/api/federation/vanity/**").permitAll();
        // Capabilities is a PUBLIC install-state projection (slug + installed +
        // mountAt + requiresRole, no internal locator/detail) — UNCHANGED. A
        // logged-out / non-admin host reads it to grey-out OPTIONAL services that are
        // absent / disabled. GET-only, caller-independent, no internal detail.
        ex.pathMatchers(HttpMethod.GET, "/api/federation/capabilities").permitAll();
        // Username availability / confusable check = INTERNAL / ROLE_SERVICE (or
        // ADMIN / SUPERADMIN). NOT public — every response is an enumeration oracle.
        // SUPERADMIN reaches it as the cross-domain infra role. Declared BEFORE the
        // authenticated catch-alls so it can never fall through to plain authenticated.
        ex.pathMatchers("/api/federation/username/**").hasAnyRole("SERVICE", "ADMIN", "SUPERADMIN");
        // Registry write + kill-switch = admin (defence-in-depth on top of the
        // @PreAuthorize method gates). SUPERADMIN added as the cross-domain infra
        // role (the per-domain CUT — admin sees only their domain's rows; superadmin
        // sees all — is enforced in the service/query layer, not here).
        ex.pathMatchers("/api/federation/modules/**").hasAnyRole("ADMIN", "SUPERADMIN");
        ex.pathMatchers("/api/federation/overrides/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // Moderation = mod or admin (decide is narrowed to admin by @PreAuthorize).
        // SUPERADMIN added as the cross-domain infra role.
        ex.pathMatchers("/api/federation/moderation/**").hasAnyRole("MOD", "ADMIN", "SUPERADMIN");
        // System findings (automated edge-AI moderation): any authenticated caller (a BFF
        // on a user's session) FILES a finding about their OWN content — POST to the bare
        // path only, subject is the JWT subject (server-derived, can't escalate). LIST +
        // RESOLVE (and any sub-path) are MOD/ADMIN/SUPERADMIN. Most-specific (the POST
        // file rule) declared FIRST so it is not swallowed by the mod-only /findings/** rule.
        ex.pathMatchers(HttpMethod.POST, "/api/federation/findings").authenticated();
        ex.pathMatchers("/api/federation/findings", "/api/federation/findings/**").hasAnyRole("MOD", "ADMIN", "SUPERADMIN");
        // Manifest read + bundle sync/serve + everything else needs a validated
        // Casdoor JWT (manifest is visibility + DOMAIN-filtered in code; bundles are
        // owner-or-admin-filtered in the service).
        ex.pathMatchers(HttpMethod.GET, "/api/federation/manifest").authenticated();
        ex.pathMatchers("/api/federation/bundles/**").authenticated();
    }

    /**
     * Dev / test profile: OpenAPI spec + Swagger UI are PUBLIC so {@code gen:fetch}
     * and the slice tests can reach the spec without a Casdoor token.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::applyHardenedHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::configureResourceServer)
                .build();
    }

    /**
     * Production profile (default — neither {@code dev} nor {@code test}): the
     * OpenAPI spec + Swagger UI require ROLE_ADMIN / ROLE_SUPERADMIN so the API
     * contract is never publicly reachable. Every non-spec route is identical to
     * dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::applyHardenedHeaders)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::configureResourceServer)
                .build();
    }

    /**
     * Resource-server wiring shared by both chains. Multi-issuer is OPT-IN: swap to
     * the per-issuer authentication-manager resolver ONLY when BOTH a resolver was
     * contributed by {@link TenancyResourceServerConfig} AND the registry is
     * genuinely multi-issuer (more than the single back-compat entry). Gating on
     * {@code isMultiIssuer()} — not merely {@code resolver != null} — keeps a
     * single-issuer cluster on the EXISTING issuer-uri {@code o.jwt(...)} path even
     * if the tenancy conditional ever activates with just the lone back-compat
     * issuer. In true multi-brand mode each trusted per-brand Casdoor validates its
     * own tokens (unknown iss -> 401, fail-closed).
     */
    private void configureResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * The org role hierarchy for METHOD security ({@code @PreAuthorize}). Mirrors the
     * web-filter intent (and admin-bff's identical bean) so a SUPERADMIN satisfies a
     * {@code hasRole('ADMIN')} / {@code hasAnyRole('SERVICE','ADMIN')} method gate — the
     * "cross-domain infra role reaches every privileged surface" contract. Without this
     * bean {@code @EnableReactiveMethodSecurity} does NO hierarchy expansion, so the
     * narrower controller gates on {@code UsernameAvailabilityController}
     * (availability/check/confusables) wrongly 403'd SUPERADMIN even though the
     * {@code /api/federation/username/**} path rule and the controller's own OpenAPI
     * contract admit it. SUPERADMIN does NOT imply ADMIN⇄MOD (siblings); only the
     * top-down edges are declared.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    @Bean
    MethodSecurityExpressionHandler federationMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        var handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT -&gt; authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical.
     */
    private Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(
                domainRegistry, new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindow));
    }
}
