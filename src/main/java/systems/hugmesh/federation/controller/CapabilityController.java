package systems.hugmesh.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import systems.hugmesh.federation.model.CapabilityDto;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.service.CapabilityService;

/**
 * Public install-state projection — {@code GET /api/federation/capabilities}.
 *
 * <p>Returns a narrow, public-safe descriptor per registered federation module
 * ({@code slug + installed + mountAt + requiresRole}) so a logged-out or non-admin
 * Angular host can grey-out OPTIONAL services (forum / mastodon / matrix / games)
 * that are absent or disabled — WITHOUT requiring a JWT.
 *
 * <p>This is the public sibling of {@code GET /api/federation/manifest}: the manifest
 * is {@code authenticated()} + visibility-filtered (an anonymous caller gets 401, and
 * internal remotes are stripped for non-admins), so a logged-out host could never learn
 * an optional service exists through the manifest and therefore cannot drive greying.
 *
 * <h2>Security gating</h2>
 * <p>{@code GET /api/federation/capabilities} is {@code permitAll} (see
 * {@link systems.hugmesh.federation.config.SecurityConfig}, declared BEFORE the
 * authenticated catch-all — exactly like {@code /api/federation/vanity}). It is safe
 * because:
 * <ul>
 *   <li>Only a narrow, public-safe shape is returned — no internal locators or details.</li>
 *   <li>Per-user vanity fragments ({@code profile-<username>}) are EXCLUDED from the
 *       projection so this endpoint is not a username enumeration oracle.</li>
 *   <li>GET-only — it can never mutate state.</li>
 * </ul>
 *
 * <h2>Domain scoping</h2>
 * <p>Even though the endpoint is {@code permitAll}, it is DOMAIN-scoped:
 * <ul>
 *   <li>An anonymous caller ({@code jwt == null}) resolves to the {@code "default"}
 *       domain (single-issuer / logged-out behaviour). Note: {@link PrincipalDomain#resolve}
 *       fails-closed to {@code NO_DOMAIN} for a null JWT, so the null case is
 *       explicitly mapped here to preserve the pre-commons default-domain behaviour.</li>
 *   <li>An authenticated per-domain caller sees only their own brand's registered
 *       services.</li>
 *   <li>SUPERADMIN sees all brands (the cross-domain infra view).</li>
 * </ul>
 * The domain is derived from the cryptographically-validated issuer, never a spoofable
 * claim, so this {@code permitAll} endpoint cannot become a cross-brand registry oracle.
 *
 * @see CapabilityService
 * @see systems.hugmesh.federation.config.SecurityConfig
 */
@Tag(name = "Capabilities",
        description = "PUBLIC install-state projection (slug + installed + mountAt + requiresRole). "
                + "Drives host greying-out of absent/disabled optional services. Public read — no JWT required.")
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
            Returns one public-safe descriptor per registered, non-fragment federation
            module — <code>{slug, installed, mountAt, requiresRole}</code> — ordered
            by slug. <code>installed</code> is <code>true</code> when the module's row
            is enabled AND circuit-closed (serveable right now).

            <h4>Presence / state rules</h4>
            <ul>
              <li>An OPTIONAL service that was never registered is <em>absent</em> from
                  the list — the host greys it out by absence.</li>
              <li>A registered-but-disabled or circuit-broken service appears with
                  <code>installed=false</code> — the host greys it out by state.</li>
            </ul>

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller</th><th>Domain scope</th></tr>
              <tr><td>Anonymous (no JWT)</td>
                  <td><code>"default"</code> domain only</td></tr>
              <tr><td>ROLE_USER / ROLE_MOD / ROLE_ADMIN</td>
                  <td>Own brand only</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>All brands (control-plane view)</td></tr>
            </table>

            <p>Public read — no JWT required. The host uses this (NOT the
            authenticated, visibility-filtered manifest) to grey-out absent services.
            Always rendered from Postgres; no cache (must reflect install-state
            changes immediately).
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Capability list returned — empty array when no non-fragment modules "
                + "are registered for the resolved domain."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying federation_modules. Check server logs.")
    })
    @GetMapping
    public Flux<CapabilityDto> capabilities(@AuthenticationPrincipal Jwt jwt) {
        // DOMAIN-scoped even though this is permitAll. An ANONYMOUS caller (jwt == null)
        // resolves to the "default" domain — we must NOT call PrincipalDomain.resolve(null, ...)
        // here because commons fails-closed to NO_DOMAIN for a null JWT (a null principal
        // proves no tenant), and NO_DOMAIN would match nothing. Instead we explicitly map
        // null → forDomain("default") to preserve the pre-commons single-issuer behaviour.
        // An AUTHENTICATED caller still resolves to their cryptographically-validated
        // issuer domain (or the cross-domain SUPERADMIN tier).
        PrincipalDomain scope = jwt == null
                ? PrincipalDomain.forDomain(DomainRegistry.DEFAULT_DOMAIN)
                : PrincipalDomain.resolve(jwt, domains);
        return capabilities.capabilities(scope);
    }
}
