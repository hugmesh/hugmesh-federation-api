package systems.snapdragon.federation.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Casdoor-aware OAuth2 resource-server security for snapdragon-federation-api
 * (reactive WebFlux). {@code @EnableReactiveMethodSecurity} activates the
 * {@code @PreAuthorize("hasRole('ADMIN')")} gates on the registry / override /
 * moderation controllers.
 *
 * <p>The JWT->authority mapping ({@link #casdoorAuthoritiesConverter}) is COPIED
 * VERBATIM from snapdragon-admin-bff-api / snapdragon-actions / snapdragon-gateway:
 * the Casdoor {@code roles} claim (string or {@code {name}} objects),
 * {@code permissions}, and {@code isAdmin} become authorities, plus a
 * {@code ROLE_USER} floor.
 *
 * <p>Gating:
 * <ul>
 *   <li>vanity resolve ({@code GET /api/federation/vanity/**}) = permitAll
 *       (PUBLIC — the public profile served at {@code <username>.<domain>};
 *       VanityService only ever returns public/enabled/circuit-closed fragments);</li>
 *   <li>manifest read ({@code GET /api/federation/manifest}) = authenticated
 *       (visibility/role-filtered in code by ManifestService);</li>
 *   <li>username availability / confusable check
 *       ({@code /api/federation/username/**}) = ROLE_SERVICE/ADMIN (INTERNAL — an
 *       enumeration oracle, never public; override + debug narrowed to ADMIN by
 *       method security);</li>
 *   <li>module-write ({@code /api/federation/modules/**}), overrides
 *       ({@code /api/federation/overrides/**}) = ROLE_ADMIN;</li>
 *   <li>moderation ({@code /api/federation/moderation/**}) = ROLE_MOD/ADMIN
 *       (method-security narrows decide to ROLE_ADMIN);</li>
 *   <li>bundles ({@code /api/federation/bundles/**}) = authenticated
 *       (owner-or-admin enforced in the service: owner = JWT subject);</li>
 *   <li>springdoc spec/UI = permitAll under dev/test, ROLE_ADMIN in prod.</li>
 * </ul>
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Shared route rules common to BOTH profiles. The ONLY per-profile difference
     * is how {@link #SPEC_PATHS} is gated, so every other route lives here to keep
     * the two chains in lockstep (mirrors admin-bff).
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
        // mountAt + requiresRole, no internal locator/detail) — a LOGGED-OUT or
        // non-admin host reads it to grey-out OPTIONAL services that are absent /
        // disabled. It MUST be public: the manifest is authenticated() +
        // visibility-filtered (anon -> 401, internal remotes stripped for
        // non-admins), so a logged-out host can't use it to drive greying. Safe
        // because the projection is GET-only (never mutates), caller-independent
        // (same body for all), and exposes no internal detail. Declared BEFORE the
        // authenticated catch-alls so it can never fall through to authenticated —
        // mirrors the /api/federation/vanity public read rule above.
        ex.pathMatchers(HttpMethod.GET, "/api/federation/capabilities").permitAll();
        // Username availability / confusable check = INTERNAL / ROLE_SERVICE (or
        // ADMIN). NOT public — every response is an enumeration oracle (matchedWith
        // names the colliding username / reserved label). The registration mint
        // paths (Casdoor pre-signup webhook, OAuth handle mint, actions / user-bff /
        // admin-bff) call it with an internal service credential; the ADMIN-only
        // override + /confusables debug are narrowed further by @PreAuthorize.
        // Declared BEFORE the authenticated catch-alls so it can never fall through
        // to plain authenticated.
        ex.pathMatchers("/api/federation/username/**").hasAnyRole("SERVICE", "ADMIN");
        // Registry write + kill-switch = admin only (defence-in-depth on top of
        // the @PreAuthorize method gates).
        ex.pathMatchers("/api/federation/modules/**").hasRole("ADMIN");
        ex.pathMatchers("/api/federation/overrides/**").hasRole("ADMIN");
        // Moderation = mod or admin (decide is narrowed to admin by @PreAuthorize).
        ex.pathMatchers("/api/federation/moderation/**").hasAnyRole("MOD", "ADMIN");
        // Manifest read + bundle sync/serve + everything else needs a validated
        // Casdoor JWT (manifest is visibility-filtered in code; bundles are
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
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter())))
                .build();
    }

    /**
     * Production profile (default — neither {@code dev} nor {@code test}): the
     * OpenAPI spec + Swagger UI require ROLE_ADMIN so the API contract is never
     * publicly reachable. Every non-spec route is identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasRole("ADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter())))
                .build();
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor claim -> Spring authority mapping. Package-private + static so it can
     * be unit-tested directly against synthetic {@link Jwt}s (identical logic to
     * the admin-bff / gateway / actions converter).
     */
    static Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            Object rolesClaim = jwt.getClaim("roles");
            if (rolesClaim instanceof Collection<?> list) {
                for (Object r : list) {
                    String name = roleNameOf(r);
                    if (!name.isBlank()) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + name.trim().toUpperCase()));
                    }
                }
            }

            Object permsClaim = jwt.getClaim("permissions");
            if (permsClaim instanceof Collection<?> list) {
                for (Object p : list) {
                    if (p != null) authorities.add(new SimpleGrantedAuthority(p.toString().trim()));
                }
            }

            if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) {
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }

            return Flux.fromIterable(authorities);
        };
    }

    private static String roleNameOf(Object item) {
        if (item instanceof String s) return s;
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s;
        }
        return "";
    }
}
