package systems.hugmesh.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.model.AdminModuleUpsertRequest;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.service.AdminModuleService;
import systems.hugmesh.federation.web.ValidationPatterns;

/**
 * SUPERADMIN federation-module admin — the create-and-federate wizard's write
 * surface over {@code federation_modules}
 * ({@code /api/federation/admin/modules}).
 *
 * <p>This is the cross-brand provisioning tooling the
 * {@link ModuleRegistryController} javadoc defers to: admin-bff's superadmin
 * Service Store calls it (via {@code RestFederationModuleClient}) to register a
 * freshly-deployed service as a micro-frontend remote. Three verbs only:
 * full-registry read, idempotent upsert-by-slug, and a REVERSIBLE soft-disable
 * ({@code enabled=false} — never the hard delete, which stays exclusively on
 * {@code DELETE /api/federation/modules/{slug}}).
 *
 * <h2>Security gating</h2>
 * <p>All paths under {@code /api/federation/admin/modules/**} require
 * {@code ROLE_SUPERADMIN} — and ONLY it — at both the path level (see
 * {@link systems.hugmesh.federation.config.SecurityConfig}) and this class's
 * {@code @PreAuthorize}. Defence-in-depth: both gates must pass. Nothing sits
 * above SUPERADMIN in the role hierarchy, so a per-brand {@code ROLE_ADMIN} is
 * 403 here — this surface writes cross-brand control-plane state; per-brand
 * admins have their own domain-pinned {@code /api/federation/modules} registry.
 *
 * <h2>Domain + invariant stamping</h2>
 * <p>{@code domain} is never accepted from a request body: a create lands in
 * {@code "default"} (the SUPERADMIN write convention) and a refresh never moves
 * an existing row's brand. Every write re-enforces the manifest read-path
 * invariants — see {@link AdminModuleService} for the guard catalogue
 * (profile-slug vocabulary, absolute http(s) entry URL, metadata
 * {@code mountAt}/{@code requiresRole} shapes, circuit-state immutability).
 *
 * @see AdminModuleService
 * @see ModuleRegistryController
 * @see systems.hugmesh.federation.config.SecurityConfig
 */
@Tag(name = "Admin Module Registry",
        description = "SUPERADMIN-only federation-module admin: full registry read, "
                + "upsert-by-slug, soft-disable. Cross-domain.")
@RestController
@RequestMapping("/api/federation/admin/modules")
@PreAuthorize("hasRole('SUPERADMIN')")
@Validated
public class AdminModuleController {

    private final AdminModuleService admin;
    private final DomainRegistry domains;

    public AdminModuleController(AdminModuleService admin, DomainRegistry domains) {
        this.admin = admin;
        this.domains = domains;
    }

    // -------------------------------------------------------------------------
    // Read
    // -------------------------------------------------------------------------

    @Operation(
        summary = "List EVERY registered module across all brands (full registry state).",
        description = """
            Returns every <code>federation_modules</code> row in every domain,
            INCLUDING disabled, circuit-open and internal-visibility rows — the
            registry's complete state, not the manifest-filtered public view. The
            wizard needs to see what is registered-but-dark; the manifest read path
            deliberately hides exactly those rows.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>ALL brands — every row regardless of state</td></tr>
              <tr><td>ROLE_ADMIN (or below)</td>
                  <td>403 — per-brand admins use <code>/api/federation/modules</code></td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "List returned — empty array when the registry is empty."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_SUPERADMIN (ROLE_ADMIN is NOT admitted here)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying federation_modules. Check server logs.")
    })
    @GetMapping
    public Flux<FederationModule> list(@AuthenticationPrincipal Jwt jwt) {
        return admin.list(PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Upsert
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Upsert a module by slug (create when absent, refresh in place when present).",
        description = """
            Idempotent upsert keyed on <code>slug</code>: the wizard re-POSTs the
            same slug on every federate action, so this endpoint deliberately
            returns 200 with the persisted row for BOTH the create and the refresh
            leg (no 201/200 split — the caller treats them identically).

            <h4>Create defaults</h4>
            <code>kind=remote-shell</code>, <code>visibility=internal</code> (a
            freshly-federated service stays dark until deliberately made public),
            <code>enabled=false</code>, <code>circuitState=closed</code>,
            <code>displayName=slug</code>, <code>version=1.0.0</code>,
            <code>domain="default"</code> (SUPERADMIN write convention — never from
            the body).

            <h4>Refresh semantics</h4>
            <code>remoteEntryUrl</code> + <code>exposedModule</code> (required in
            every body) are always applied; <code>displayName, kind, version,
            visibility, enabled, metadata</code> only when supplied — an OMITTED
            <code>enabled</code> leaves an existing row's flag UNCHANGED (unlike
            the entity-bodied <code>PUT /api/federation/modules/{slug}</code>).
            <code>slug, domain, circuitState, ownerUserId, contentHash,
            createdAt</code> never move: a circuit-break kill SURVIVES re-POSTs and
            is lifted only via <code>POST /api/federation/overrides/{slug}/rearm</code>.

            <h4>Write guards (400)</h4>
            <code>profile-*</code> slugs are rejected (vanity-publish territory —
            and the DB's reserved-profile-slug CHECK would refuse the worst of them
            anyway); <code>remoteEntryUrl</code> must be an absolute http(s) URL;
            <code>metadata</code> must be a JSON object string whose
            <code>mountAt</code> (<code>/path</code>) and <code>requiresRole</code>
            (bare role name) keys are well-shaped when present.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_SUPERADMIN</td><td>Upsert lands (domain="default" on create)</td></tr>
              <tr><td>ROLE_ADMIN (or below)</td><td>403</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Module upserted and returned — both the first-time create and every "
                + "subsequent refresh land here."),
        @ApiResponse(responseCode = "400",
            description = "Request body fails validation (missing slug/remoteEntryUrl/exposedModule, "
                + "non-DNS-label slug, kind outside remote-shell|fragment, non-http(s) "
                + "remoteEntryUrl, reserved profile-* slug, or malformed metadata JSON / "
                + "mountAt / requiresRole)."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_SUPERADMIN (ROLE_ADMIN is NOT admitted here)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @PostMapping
    public Mono<FederationModule> upsert(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody AdminModuleUpsertRequest request) {
        // Domain is always stamped in the service from the validated scope — never
        // accepted from the request body (and a refresh never moves a row's brand).
        return admin.upsert(request, PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Soft-disable
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Soft-disable a module by slug (enabled=false — reversible, never a hard delete).",
        description = """
            Flips <code>enabled=false</code> on the row and nothing else: the next
            manifest render drops it DB-side, while the registry keeps the row for
            inspection and a later re-enabling upsert (<code>POST</code> with
            <code>enabled=true</code>). <code>visibility</code> and
            <code>circuitState</code> are left untouched — this is the reversible
            registry off-switch, not the vanity unpublish (which also flips
            visibility) nor the circuit-break kill. The HARD delete remains
            exclusively <code>DELETE /api/federation/modules/{slug}</code>.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_SUPERADMIN</td><td>Any slug in any brand</td></tr>
              <tr><td>ROLE_ADMIN (or below)</td><td>403</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "204",
            description = "Module soft-disabled; no body returned. Idempotent on an "
                + "already-disabled row."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_SUPERADMIN (ROLE_ADMIN is NOT admitted here)."),
        @ApiResponse(responseCode = "404",
            description = "No module with that slug in any domain."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @DeleteMapping("/{slug}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> softDisable(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        return admin.softDisable(slug, PrincipalDomain.resolve(jwt, domains));
    }
}
