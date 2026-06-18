package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.CapabilityDto;
import systems.snapdragon.federation.security.DomainRegistry;
import systems.snapdragon.federation.security.DomainScope;
import systems.snapdragon.federation.service.CapabilityService;

/**
 * PUBLIC capability projection — {@code GET /api/federation/capabilities}.
 *
 * <p>The install-state list a LOGGED-OUT or non-admin host reads to grey-out
 * OPTIONAL services (forum / mastodon / matrix / games) that are absent or
 * disabled. This is the public sibling of {@code GET /api/federation/manifest}:
 * the manifest is {@code authenticated()} + visibility-filtered (anonymous → 401,
 * and internal remotes are stripped for non-admins), so a logged-out host could
 * never learn an optional service exists — it CANNOT drive greying. This endpoint
 * is {@code permitAll} (see {@link systems.snapdragon.federation.config.SecurityConfig};
 * declared BEFORE the authenticated catch-all, exactly like the
 * {@code /api/federation/vanity} public read rule) and returns a deliberately
 * NARROW, public-safe projection (slug + installed + mountAt + requiresRole only —
 * no internal locator/detail).
 *
 * <p>GET-only so it can never mutate. It is DOMAIN-scoped (and excludes per-user
 * {@code profile-<username>} vanity fragments): an anonymous caller resolves to the
 * {@code "default"} domain, an authenticated per-domain caller sees only their own
 * brand's services, and SUPERADMIN sees all — so this {@code permitAll} endpoint
 * cannot be a cross-brand registry / username enumeration oracle. The manifest /
 * override read paths are untouched: this is purely additive.
 */
@Tag(name = "Capabilities",
        description = "PUBLIC install-state projection (slug + installed + mountAt + requiresRole). "
                + "Drives host greying-out of absent/disabled optional services. Public read — no JWT.")
@RestController
@RequestMapping("/api/federation/capabilities")
public class CapabilityController {

    private final CapabilityService capabilities;
    private final DomainRegistry domains;

    public CapabilityController(CapabilityService capabilities, DomainRegistry domains) {
        this.capabilities = capabilities;
        this.domains = domains;
    }

    @Operation(
        summary = "Public install-state list of registered federation modules.",
        description = """
            Returns one public-safe descriptor per registered federation module —
            {slug, installed, mountAt, requiresRole} — ordered by slug. `installed`
            is true when the module's row is enabled AND circuit-closed (serveable
            right now). An OPTIONAL service that was never registered is ABSENT from
            the list (host greys it out by absence); a registered-but-disabled /
            circuit-broken one appears with installed=false (host greys it out by
            state). Public read — no JWT, no internal locator/detail. The host uses
            this (NOT the authed, visibility-filtered manifest) to grey-out absent
            services.
            """)
    @GetMapping
    public Flux<CapabilityDto> capabilities(@AuthenticationPrincipal Jwt jwt) {
        // DOMAIN-scoped even though this is permitAll: an ANONYMOUS caller (jwt==null)
        // resolves to the "default" domain (single-issuer / logged-out behaviour); an
        // authenticated per-domain caller sees ONLY their own brand's registered
        // services; SUPERADMIN (cross-domain infra role) sees every brand's. The domain
        // is derived from the cryptographically-validated issuer (never a spoofable
        // claim) and fragment slugs are excluded in the query — so this public endpoint
        // can never become a cross-brand registry / username enumeration oracle.
        return capabilities.capabilities(DomainScope.resolve(jwt, domains));
    }
}
