package systems.hugmesh.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationManifestDto;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.service.ManifestService;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Runtime federation manifest, served from PostgreSQL (Cassandra write-through
 * cached). Lifted from the games {@code FederationController}: the Angular host
 * bootstrap fetches this and feeds {@code remotes} into native-federation's
 * {@code initFederation(...)} before {@code bootstrapApplication}, so new remote
 * modules appear without redeploying the host shell.
 *
 * <p>Gated as {@code authenticated} (see SecurityConfig); the manifest is then
 * visibility/role-filtered IN CODE by {@link ManifestService} against the
 * caller's authorities. Internal-visibility remotes only appear for
 * ROLE_ADMIN / ROLE_INTERNAL callers; circuit-open + disabled remotes are
 * dropped for everyone.
 */
@Tag(name = "Federation", description = "Runtime module-federation manifest (DB-backed, visibility + kill-switch filtered).")
@RestController
@RequestMapping("/api/federation")
public class FederationController {

    private final ManifestService manifest;
    private final DomainRegistry domains;

    public FederationController(ManifestService manifest, DomainRegistry domains) {
        this.manifest = manifest;
        this.domains = domains;
    }

    @Operation(
        summary = "Active federation manifest",
        description = """
            Returns the runtime module-federation manifest: every enabled,\s\
            circuit-closed <code>federation_modules</code> row the caller may\s\
            see, ordered by kind then slug, as\s\
            <code>{generatedAt, remotes[]}</code>.

            <p>The Angular host shell calls this endpoint on bootstrap and on\s\
            every full reload, feeding <code>remotes[]</code> into\s\
            native-federation's <code>initFederation(…)</code> before\s\
            <code>bootstrapApplication()</code>.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Rows visible</th><th>Domain scope</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD</td>
                  <td><code>visibility='public'</code> only</td>
                  <td>own brand only</td></tr>
              <tr><td>ROLE_ADMIN / ROLE_INTERNAL</td>
                  <td><code>public</code> + <code>internal</code></td>
                  <td>own brand only</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td><code>public</code> + <code>internal</code></td>
                  <td>ALL brands (control-plane view)</td></tr>
            </table>

            <h4>Kill-switch / scope-override filters (applied in code)</h4>
            <ul>
              <li><b>scope=all</b> active override → drops EVERY module from\s\
                  the manifest (global kill).</li>
              <li><b>scope=user</b> active override → drops all modules owned\s\
                  by the targeted Casdoor subject.</li>
              <li><b>scope=role</b> active override → drops modules whose\s\
                  <code>metadata.requiresRole</code> matches the target role.</li>
            </ul>
            An override is active while its <code>cleared_at IS NULL</code>;\s\
            clearing it rearms the affected modules immediately on the next\s\
            render.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Manifest returned — remotes[] may be empty if no "
                + "modules pass the caller's visibility and scope-override filters."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT. "
                + "Obtain a fresh token from the Casdoor SSO and retry."),
        @ApiResponse(responseCode = "500",
            description = "Postgres or cache error while rendering the manifest. "
                + "The manifest cache (Cassandra) is best-effort; a cache failure "
                + "alone does not produce a 500 — only a Postgres failure does. "
                + "Check server logs for details.")
    })
    @GetMapping("/manifest")
    public Mono<FederationManifestDto> manifest(Authentication auth, @AuthenticationPrincipal Jwt jwt) {
        // The manifest is DOMAIN-scoped: a per-domain principal sees ONLY their own
        // brand's remotes; SUPERADMIN (cross-domain infra role) sees every brand's.
        // The domain is derived from the cryptographically-validated issuer (via the
        // registry), never a spoofable claim — fail-closed to a no-match domain when
        // the issuer is unknown in multi-brand mode.
        return manifest.render(authoritiesOf(auth), PrincipalDomain.resolve(jwt, domains));
    }

    static Set<String> authoritiesOf(Authentication auth) {
        if (auth == null || auth.getAuthorities() == null) return Set.of();
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }
}
