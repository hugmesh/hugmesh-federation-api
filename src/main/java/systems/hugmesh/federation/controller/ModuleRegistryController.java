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
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationModule;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.service.ModuleRegistryService;
import systems.hugmesh.federation.web.ValidationPatterns;

/**
 * Module registry CRUD — the admin-bff / owner-client write surface for
 * {@code federation_modules}.
 *
 * <p>This controller manages the canonical registry of Angular micro-frontend
 * modules: registering new remotes, updating their metadata (remoteEntryUrl,
 * circuit state, visibility, etc.), and deleting them. A create additionally
 * mints the confusable-skeleton cache row when the new module is a
 * {@code profile-<username>} vanity fragment (best-effort, never fails the create).
 *
 * <h2>Security gating</h2>
 * <p>All paths under {@code /api/federation/modules/**} require
 * {@code ROLE_ADMIN} or {@code ROLE_SUPERADMIN} at both the path level (see
 * {@link systems.hugmesh.federation.config.SecurityConfig}) and the class-level
 * {@code @PreAuthorize} annotation. This is defence-in-depth: both gates must be
 * passed. {@code ROLE_USER} and {@code ROLE_MOD} are never admitted here.
 *
 * <h2>Domain scoping</h2>
 * <p>Every operation is DOMAIN-scoped from the validated JWT issuer via
 * {@link PrincipalDomain#resolve}:
 * <ul>
 *   <li><b>Per-domain ADMIN</b> — pinned to their brand; a slug or domain that
 *       belongs to another brand is invisible (returns 404 or empty) rather than 403,
 *       to avoid cross-brand discovery.</li>
 *   <li><b>SUPERADMIN</b> — un-pinned, cross-domain control-plane view.</li>
 * </ul>
 * The {@code domain} column is ALWAYS stamped from the authenticated scope on
 * writes — never accepted from the request body.
 *
 * @see ModuleRegistryService
 * @see systems.hugmesh.federation.config.SecurityConfig
 */
@Tag(name = "Module Registry",
        description = "Federation module registry CRUD. ROLE_ADMIN required. DOMAIN-scoped.")
@RestController
@RequestMapping("/api/federation/modules")
@PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
@Validated
public class ModuleRegistryController {

    private final ModuleRegistryService registry;
    private final DomainRegistry domains;

    public ModuleRegistryController(ModuleRegistryService registry, DomainRegistry domains) {
        this.registry = registry;
        this.domains = domains;
    }

    // -------------------------------------------------------------------------
    // Reads
    // -------------------------------------------------------------------------

    @Operation(
        summary = "List registered modules in the caller's domain (SUPERADMIN: all domains).",
        description = """
            Returns every <code>federation_modules</code> row visible to the caller,
            including disabled and circuit-open rows (the full registry state, not
            the manifest-filtered public view).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Rows returned</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand only — all modules regardless of state</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>ALL brands — the complete cross-domain registry</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "List returned — empty array when no modules are registered for "
                + "the caller's domain."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying federation_modules. Check server logs.")
    })
    @GetMapping
    public Flux<FederationModule> list(@AuthenticationPrincipal Jwt jwt) {
        return registry.list(PrincipalDomain.resolve(jwt, domains));
    }

    @Operation(
        summary = "Get one module by slug (scoped to the caller's domain; SUPERADMIN: any).",
        description = """
            Loads a single <code>federation_modules</code> row by its slug.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand's row only; cross-brand slug → 404</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Any slug in any brand</td></tr>
            </table>

            <p>A cross-brand slug returns 404 (not 403) to avoid leaking whether
            the slug exists in another brand.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Module returned."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No module with that slug in the caller's domain (or in any domain "
                + "for SUPERADMIN)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @GetMapping("/{slug}")
    public Mono<FederationModule> get(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        return registry.get(slug, PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Write
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Register a new module (stamped with the caller's domain).",
        description = """
            Inserts a new <code>federation_modules</code> row. The <code>domain</code>
            column is OVERWRITTEN from the authenticated JWT scope — the value in the
            request body is ignored — so a caller cannot plant a row in another brand.

            <p>If the new module is a <code>profile-&lt;username&gt;</code> fragment
            (<code>kind=fragment</code>), the confusable-skeleton cache row for
            <code>&lt;username&gt;</code> is minted in the same reactive flow
            (best-effort: a skeleton-write failure never fails the create).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Domain stamped</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Caller's own brand</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td><code>"default"</code> (the SUPERADMIN admin-tooling surface is
                      <code>/api/federation/admin/modules</code>)</td></tr>
            </table>

            <p>Default field values applied on create: <code>visibility='public'</code>,
            <code>circuit_state='closed'</code>, <code>enabled=true</code>.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "201",
            description = "Module registered and returned."),
        @ApiResponse(responseCode = "400",
            description = "Request body fails the OnCreate validation group constraints."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "409",
            description = "A module with the same slug already exists (slug UNIQUE constraint "
                + "violation)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<FederationModule> create(
            @AuthenticationPrincipal Jwt jwt,
            @Validated(FederationModule.OnCreate.class) @RequestBody FederationModule module) {
        // Domain is always stamped in the service from the validated scope — never
        // accepted from the request body, so a caller cannot plant a row cross-brand.
        return registry.create(module, PrincipalDomain.resolve(jwt, domains));
    }

    @Operation(
        summary = "Update a module by slug (partial; scoped to the caller's domain; SUPERADMIN: any).",
        description = """
            Applies a partial patch to an existing module. Only non-null fields in the
            request body are applied; the <code>domain</code> column is NOT patchable —
            a module stays in its registered brand forever.

            <h4>Patchable fields</h4>
            <code>displayName, kind, remoteEntryUrl, exposedModule, version,
            contentHash, visibility, circuitState, metadata, enabled</code>

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand's module only; cross-brand slug → 404</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Any module in any brand</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Module updated and returned."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern, or request "
                + "body is invalid."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No module with that slug in the caller's domain (or in any domain "
                + "for SUPERADMIN)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @PutMapping("/{slug}")
    public Mono<FederationModule> update(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug,
            @Valid @RequestBody FederationModule patch) {
        return registry.update(slug, patch, PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Delete a module by slug (scoped to the caller's domain; SUPERADMIN: any).",
        description = """
            Hard-deletes the <code>federation_modules</code> row for the given slug.
            The module disappears from the manifest on the next render. If you want
            a recoverable kill-switch rather than a permanent delete, use
            <code>POST /api/federation/overrides</code> with
            <code>action=circuit-break</code> or <code>action=unpublish</code> instead.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand's module only; cross-brand slug → 404</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Any module in any brand</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "204",
            description = "Module deleted; no body returned."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No module with that slug in the caller's domain (or in any domain "
                + "for SUPERADMIN)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @DeleteMapping("/{slug}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        return registry.delete(slug, PrincipalDomain.resolve(jwt, domains));
    }
}
