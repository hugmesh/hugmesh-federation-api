package systems.snapdragon.federation.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.security.DomainRegistry;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CONFIG-GATED, backward-compatible multi-issuer (per-brand Casdoor) wiring.
 * COPIED VERBATIM (package adjusted) from the canonical
 * {@code systems.snapdragon.gateway.config.TenancyResourceServerConfig}.
 *
 * <p>Contributes a per-issuer {@link ReactiveAuthenticationManagerResolver} ONLY
 * when {@code app.tenancy.issuers} actually carries issuer=domain pairs (the
 * {@code .contains('=')} guard) — NOT merely when the property is "present" with
 * the empty {@code ${APP_TENANCY_ISSUERS:}} default, which a bare
 * {@code @ConditionalOnProperty(name=...)} would have treated as present-and-true
 * and so ALWAYS activated. {@link SecurityConfig} additionally only swaps onto this
 * resolver when {@link DomainRegistry#isMultiIssuer()} (more than the lone
 * back-compat entry), so a single-issuer cluster keeps the existing single
 * {@code o.jwt(...)} jwk-set-uri / issuer-uri path verbatim and is byte-for-byte
 * unchanged.
 *
 * <p><b>Fail-closed on unknown issuer.</b> The resolver's allowlist is exactly
 * {@link DomainRegistry#trustedIssuers()} (the configured per-brand Casdoors). A
 * token whose {@code iss} is not in that set gets NO manager and 401s before any
 * authority is emitted.
 *
 * <p><b>Custom converter preserved per issuer.</b> The per-issuer
 * {@link JwtReactiveAuthenticationManager} is built ourselves and set with the SAME
 * Casdoor authorities converter the single-issuer path uses, so the
 * {@code DOMAIN_<x>} authority is emitted in multi-issuer mode too — identical
 * authority output to the single-issuer path.
 */
@Configuration
// Fire ONLY when app.tenancy.issuers genuinely carries issuer=domain pairs. The
// '=' guard makes the empty ${APP_TENANCY_ISSUERS:} default a no-op: an empty
// string is "present and not false" to @ConditionalOnProperty, which would have
// activated this bean (and silently routed single-issuer clusters through the
// resolver / OIDC discovery). A valid CSV always contains at least one '='.
@ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")
public class TenancyResourceServerConfig {

    private final DomainRegistry domainRegistry;

    /** Explicit issuer-uri of the lone back-compat issuer (the single-issuer
     *  {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}). Paired with
     *  {@link #backCompatJwkSetUri} to build a discovery-free decoder for it when a
     *  jwk-set-uri is also configured. */
    private final String backCompatIssuer;

    /** Explicit jwk-set-uri of the lone back-compat issuer — used to build the
     *  per-issuer decoder WITHOUT OIDC discovery. Empty on pure multi-brand configs
     *  (each brand decoder discovers from its own iss) — this BFF's back-compat path
     *  is issuer-uri (OIDC discovery), so this is normally empty. */
    private final String backCompatJwkSetUri;

    /** D8 MFA floor — ships DARK. SAME {@code app.mfa.enabled} (default
     *  {@code false}) / {@code app.mfa.freshness-window} (default 10m) the
     *  single-issuer {@link SecurityConfig} reads, threaded into the SAME
     *  {@link CasdoorAuthorities.MfaConfig} so the multi-issuer path derives the
     *  {@code MFA_SATISFIED} marker BYTE-IDENTICALLY to the single-issuer path. */
    private final boolean mfaEnabled;

    private final long mfaFreshnessWindow;

    public TenancyResourceServerConfig(
            DomainRegistry domainRegistry,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String backCompatIssuer,
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}") String backCompatJwkSetUri,
            @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
            @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindow) {
        this.domainRegistry = domainRegistry;
        this.backCompatIssuer = trimSlash(backCompatIssuer);
        this.backCompatJwkSetUri = backCompatJwkSetUri == null ? "" : backCompatJwkSetUri.trim();
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindow = mfaFreshnessWindow;
    }

    private static String trimSlash(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    @Bean
    ReactiveAuthenticationManagerResolver<ServerWebExchange> tenantAuthManagerResolver() {
        // Cache one manager per trusted issuer (decoder construction does network
        // discovery — build lazily on first sight, never per request).
        Map<String, ReactiveAuthenticationManager> byIssuer = new ConcurrentHashMap<>();

        // Per-issuer resolver: ONLY trusted issuers (registry keys) get a manager;
        // an unknown iss yields Mono.empty() -> 401 (fail-closed).
        ReactiveAuthenticationManagerResolver<String> byIssuerResolver = issuer -> {
            if (issuer == null || !domainRegistry.isTrusted(issuer)) {
                return Mono.empty();
            }
            return Mono.just(byIssuer.computeIfAbsent(issuer, this::managerForIssuer));
        };

        JwtIssuerReactiveAuthenticationManagerResolver delegate =
                new JwtIssuerReactiveAuthenticationManagerResolver(byIssuerResolver);

        // OPT-IN, off-request-path decoder warmup — ships DARK (default off).
        // WHY: managerForIssuer(iss) -> decoderForIssuer(iss) ->
        // ReactiveJwtDecoders.fromIssuerLocation(iss) performs SYNCHRONOUS OIDC
        // discovery (blocking HTTP round-trips) at decoder-CONSTRUCTION time. On the
        // lazy path that construction is deferred to the FIRST request to touch a given
        // issuer (inside computeIfAbsent above), so that one request pays a cold-start
        // latency spike — the same spike that made the multi-issuer security slice
        // flaky against WebTestClient's 5s blocking-read budget, and that in PROD makes
        // the first authenticated request per brand slow after a restart. When enabled,
        // we pre-build every trusted issuer's manager ONCE on a daemon thread (never on
        // the event loop, never per request), so requests always hit the warm cache.
        //
        // SAFE / INERT BY DEFAULT: gated on app.tenancy.warmup-issuers (default false).
        // Best-effort — a discovery failure here is swallowed (logged at debug) and the
        // lazy path still rebuilds on first request, so a transient Casdoor outage at
        // boot can never fail-open or crash startup. Reading the flag via a property
        // lookup (not a new ctor arg) keeps the bean/ctor signature unchanged.
        warmIssuersIfEnabled(byIssuer);

        return delegate::resolve;
    }

    /** Best-effort, opt-in pre-build of every trusted issuer's manager OFF the request
     *  path. No-op unless {@code app.tenancy.warmup-issuers} (sys-prop or env
     *  {@code APP_TENANCY_WARMUP_ISSUERS}) is truthy — so the default is byte-for-byte
     *  the existing lazy path. Failures are swallowed: warmup is an optimization, never
     *  a correctness or availability dependency. */
    private void warmIssuersIfEnabled(Map<String, ReactiveAuthenticationManager> byIssuer) {
        if (!warmupEnabled()) {
            return; // DARK default — unchanged lazy behaviour
        }
        java.util.Set<String> issuers = domainRegistry.trustedIssuers();
        if (issuers.isEmpty()) {
            return;
        }
        Thread warmer = new Thread(() -> {
            for (String iss : issuers) {
                try {
                    byIssuer.computeIfAbsent(iss, this::managerForIssuer);
                } catch (RuntimeException ignored) {
                    // Discovery unreachable at boot — leave it for the lazy path to
                    // rebuild on first request. Never fail startup over a warmup miss.
                }
            }
        }, "tenancy-issuer-warmup");
        warmer.setDaemon(true);
        warmer.start();
    }

    /** Truthy iff the opt-in warmup flag is set (sys-prop {@code app.tenancy.warmup-issuers}
     *  or env {@code APP_TENANCY_WARMUP_ISSUERS}). Default false. */
    private static boolean warmupEnabled() {
        String v = System.getProperty("app.tenancy.warmup-issuers");
        if (v == null || v.isBlank()) {
            v = System.getenv("APP_TENANCY_WARMUP_ISSUERS");
        }
        return v != null && ("true".equalsIgnoreCase(v.trim()) || "1".equals(v.trim()));
    }

    /** Build the per-issuer manager wired to the SAME Casdoor authorities converter
     *  the single-issuer path uses, so the {@code DOMAIN_<x>} authority is emitted in
     *  multi-issuer mode too. */
    private ReactiveAuthenticationManager managerForIssuer(String issuer) {
        JwtReactiveAuthenticationManager mgr =
                new JwtReactiveAuthenticationManager(decoderForIssuer(issuer));
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter());
        mgr.setJwtAuthenticationConverter(converter);
        return mgr;
    }

    /** Decoder for an issuer. The lone back-compat issuer (the one with a configured
     *  jwk-set-uri) gets a discovery-free {@code withJwkSetUri} decoder + the standard
     *  exp/nbf validators + an {@code iss}-binding validator. Any other (per-brand)
     *  issuer uses {@code fromIssuerLocation} discovery (the correct behaviour for a
     *  genuinely multi-brand deployment). */
    private ReactiveJwtDecoder decoderForIssuer(String issuer) {
        String iss = trimSlash(issuer);
        if (!backCompatJwkSetUri.isEmpty() && !backCompatIssuer.isEmpty()
                && backCompatIssuer.equals(iss)) {
            NimbusReactiveJwtDecoder decoder =
                    NimbusReactiveJwtDecoder.withJwkSetUri(backCompatJwkSetUri).build();
            OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(iss);
            decoder.setJwtValidator(withIssuer);
            return decoder;
        }
        return ReactiveJwtDecoders.fromIssuerLocation(iss);
    }

    /** The Casdoor authorities converter — identical shape to
     *  {@code SecurityConfig.casdoorAuthoritiesConverter()} (kept in sync via the
     *  shared {@link CasdoorAuthorities}), with the issuer-derived {@code DOMAIN_<x>}
     *  added. */
    private Converter<Jwt, Flux<GrantedAuthority>> authoritiesConverter() {
        return CasdoorAuthorities.converter(
                domainRegistry, new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindow));
    }
}
