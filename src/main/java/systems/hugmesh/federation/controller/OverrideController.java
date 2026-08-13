package systems.hugmesh.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.model.FederationOverride;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.service.OverrideService;
import systems.hugmesh.federation.web.ValidationPatterns;

/**
 * Federation kill-switch surface — apply, rearm, and clear-scope overrides
 * on {@code federation_modules}.
 *
 * <p>An override has two effects recorded in a single audit row:
 * <ol>
 *   <li><b>Per-module mutation</b> — the targeted module's read-path fields are
 *       mutated ({@code circuit_state} / {@code enabled}, or a hard-delete),
 *       so the manifest's enabled+circuit DB finder drops it on the very next
 *       render.</li>
 *   <li><b>Scope-override active row</b> — the {@code federation_override} row's
 *       {@code scope}/{@code target} describe WHO the kill applies to
 *       ({@code all} = everything; {@code user} = an owner's modules;
 *       {@code role} = modules declaring a required role). While
 *       {@code cleared_at IS NULL} the row is active and
 *       {@link systems.hugmesh.federation.service.ManifestService} applies it
 *       across the catalogue at render time.</li>
 * </ol>
 *
 * <h2>Security gating</h2>
 * <p>All paths under {@code /api/federation/overrides/**} require
 * {@code ROLE_ADMIN} or {@code ROLE_SUPERADMIN} at both the path level (see
 * {@link systems.hugmesh.federation.config.SecurityConfig}) and the class-level
 * {@code @PreAuthorize}. This is defence-in-depth.
 *
 * <h2>Domain scoping</h2>
 * <p>Every operation is DOMAIN-scoped from the validated JWT issuer:
 * <ul>
 *   <li>A per-domain admin applies and clears overrides ONLY within their own brand
 *       — a cross-domain slug or a cross-domain source tag returns 404 / no match.</li>
 *   <li>SUPERADMIN acts across all brands.</li>
 * </ul>
 *
 * @see OverrideService
 * @see systems.hugmesh.federation.config.SecurityConfig
 * @see systems.hugmesh.federation.service.ManifestService
 */
@Tag(name = "Override",
        description = "Federation kill-switch: circuit-break / unpublish / remove a module. "
                + "ROLE_ADMIN required. DOMAIN-scoped.")
@RestController
@RequestMapping("/api/federation/overrides")
@PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
@Validated
public class OverrideController {

    private final OverrideService overrides;
    private final DomainRegistry domains;

    public OverrideController(OverrideService overrides, DomainRegistry domains) {
        this.overrides = overrides;
        this.domains = domains;
    }

    // -------------------------------------------------------------------------
    // Request body records
    // -------------------------------------------------------------------------

    /**
     * Body for {@code POST /} (apply a kill-switch override). Both {@code moduleSlug}
     * and {@code action} are required; {@code scope} is required; {@code scopeValue}
     * is optional (the userId for {@code user} scope, the role name for {@code role}
     * scope; omit / null for {@code all}).
     *
     * @param moduleSlug the targeted module slug (DNS-label-style)
     * @param scope      override scope — one of {@code all|role|user}
     * @param scopeValue optional scope key; userId for {@code user},
     *                   role name for {@code role}; null for {@code all}
     * @param action     override verb — one of {@code circuit-break|unpublish|remove}
     */
    public record ApplyRequest(
            @NotBlank(message = "moduleSlug is required")
            @Pattern(regexp = ValidationPatterns.SLUG, message = "moduleSlug must be a DNS-label-style slug")
            String moduleSlug,
            @NotBlank(message = "scope is required")
            @Pattern(regexp = ValidationPatterns.OVERRIDE_SCOPE, message = "scope must be all|role|user")
            String scope,
            @Size(max = 1024, message = "scopeValue must be at most 1024 chars") String scopeValue,
            @NotBlank(message = "action is required")
            @Pattern(regexp = ValidationPatterns.OVERRIDE_ACTION,
                    message = "action must be circuit-break|unpublish|remove") String action) {}

    /**
     * Body for {@code POST /clear} (clear an active scope override). Both fields are
     * required: {@code scope} identifies the scope kind; {@code target} is the scope
     * key (userId for {@code user}, role name for {@code role}; omit / null for
     * {@code all}).
     *
     * @param scope  scope kind — one of {@code all|role|user}
     * @param target scope key; null for {@code all}
     */
    public record ClearScopeRequest(
            @NotBlank(message = "scope is required")
            @Pattern(regexp = ValidationPatterns.OVERRIDE_SCOPE, message = "scope must be all|role|user")
            String scope,
            @Size(max = 1024, message = "target must be at most 1024 chars") String target) {}

    /**
     * Body for {@code POST /clear-source} (rearm by source tag). The {@code source}
     * is the SOURCE tag that was written when the scope override was applied — e.g.
     * {@code 'access_suspension:<id>'} — and is matched against
     * {@code federation_override.reason}. Only rows that carry THIS source tag are
     * rearmed (a different admin kill with a different / null reason is unaffected).
     *
     * @param source the source tag whose active override rows to rearm
     *               (e.g. {@code "access_suspension:42"}); max 1 024 chars
     */
    public record ClearSourceRequest(
            @NotBlank(message = "source is required")
            @Size(max = 1024, message = "source must be at most 1024 chars") String source) {}

    // -------------------------------------------------------------------------
    // List
    // -------------------------------------------------------------------------

    @Operation(
        summary = "List applied overrides in the caller's domain (SUPERADMIN: all domains).",
        description = """
            Returns the full <code>federation_override</code> audit log visible to the
            caller, ordered newest-first. Includes both active (<code>cleared_at IS NULL</code>)
            and cleared rows.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Rows visible</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand's override rows only</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>All brands' override rows</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Override audit log returned — empty array when none exist for "
                + "the caller's domain."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying federation_override. Check server logs.")
    })
    @GetMapping
    public Flux<FederationOverride> list(@AuthenticationPrincipal Jwt jwt) {
        return overrides.list(PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Apply
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Apply a kill-switch override (circuit-break / unpublish / remove).",
        description = """
            Applies an override against a module slug IN THE CALLER'S DOMAIN:
            <ul>
              <li><code>action=circuit-break</code> — sets
                  <code>circuit_state='open'</code> on the module row; manifest
                  drops it on the next render.</li>
              <li><code>action=unpublish</code>    — sets <code>enabled=false</code>.</li>
              <li><code>action=remove</code>       — hard-deletes the module row.</li>
            </ul>

            <p>In addition to the per-module mutation, a <code>federation_override</code>
            audit row is inserted with the scope / target / action / set-by / domain
            fields. While <code>cleared_at IS NULL</code> the row is <em>active</em> and
            suppresses matched modules at manifest render time (scope-override kill).

            <h4>Scope semantics</h4>
            <table>
              <tr><th>scope</th><th>target field</th><th>Suppresses</th></tr>
              <tr><td><code>all</code></td><td>NULL</td>
                  <td>EVERY module (global kill)</td></tr>
              <tr><td><code>user</code></td><td>userId (ownerUserId)</td>
                  <td>All modules owned by that user</td></tr>
              <tr><td><code>role</code></td><td>role name</td>
                  <td>Modules whose metadata.requiresRole matches</td></tr>
            </table>

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand's module only; cross-brand slug → 404</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Any module in any brand; audit row stamped with the
                      targeted module's domain</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Override applied; the new federation_override audit row is returned."),
        @ApiResponse(responseCode = "400",
            description = "moduleSlug fails the pattern, or scope / action is not a recognised "
                + "vocabulary value."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No module with that slug in the caller's domain."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @PostMapping
    public Mono<FederationOverride> apply(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ApplyRequest req) {
        // The admin's Casdoor subject is stamped as set_by — never from the request body.
        return overrides.apply(req.moduleSlug(), req.scope(), req.scopeValue(), req.action(),
                jwt.getSubject(), PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Rearm
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Re-arm a circuit-broken / unpublished module (admin recovery).",
        description = """
            Restores a module that was circuit-broken or unpublished via an override:
            sets <code>circuit_state='closed'</code> and <code>enabled=true</code>
            on the module row. The module returns to the manifest on the next render.

            <p>This endpoint targets the <em>module row</em> directly; to clear an
            <em>active scope-override row</em> (a global / user / role kill), use
            <code>POST /api/federation/overrides/clear</code> instead.

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
            description = "Module re-armed and returned with circuit_state=closed, enabled=true."),
        @ApiResponse(responseCode = "400",
            description = "moduleSlug path variable fails the DNS-label-style pattern."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No module with that slug in the caller's domain."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error. Check server logs.")
    })
    @PostMapping("/{moduleSlug}/rearm")
    public Mono<FederationModule> rearm(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                    message = "invalid moduleSlug") String moduleSlug) {
        return overrides.rearm(moduleSlug, PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Clear-scope / clear-source
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Clear (re-arm) an active scope override.",
        description = """
            Stamps <code>cleared_at</code> on the matching active
            <code>federation_override</code> row(s) so the manifest read path stops
            suppressing the affected modules (they return on the next render).

            <h4>Scope / target rules</h4>
            <table>
              <tr><th>scope</th><th>target</th></tr>
              <tr><td><code>all</code></td>
                  <td>Omit / null — clears the global kill</td></tr>
              <tr><td><code>user</code></td>
                  <td>The userId (ownerUserId) whose kill to clear</td></tr>
              <tr><td><code>role</code></td>
                  <td>The role name whose kill to clear</td></tr>
            </table>

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Clears ONLY rows in own brand; cross-brand rows are
                      unaffected</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Clears matching rows across all brands</td></tr>
            </table>

            <p>Returns the count of rows cleared (0 if no active row matched).
            Per-module recovery still uses <code>POST /{moduleSlug}/rearm</code>.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Count of cleared rows returned (Long). 0 when no active row matched."),
        @ApiResponse(responseCode = "400",
            description = "scope is not all|role|user."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while stamping cleared_at. Check server logs.")
    })
    @PostMapping("/clear")
    public Mono<Long> clearScope(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ClearScopeRequest req) {
        return overrides.clearScope(req.scope(), req.target(), PrincipalDomain.resolve(jwt, domains));
    }

    @Operation(
        summary = "Clear (re-arm) the scope override(s) created by a specific SOURCE tag.",
        description = """
            Stamps <code>cleared_at</code> on every ACTIVE <code>federation_override</code>
            row whose <code>reason</code> equals the given <code>source</code> tag
            (e.g. <code>'access_suspension:42'</code>), so the manifest read path stops
            suppressing the affected owner's modules (they return on the next render).

            <p>This is the suspension-clear (rebuild) path. Only rows that match the
            <em>exact source tag</em> are rearmed — a manual admin kill written with a
            different or null reason is never accidentally cleared.

            <h4>DOMAIN-scoped (cross-tenant security)</h4>
            <p>A per-domain admin rearms ONLY rows in their own brand — the matched set
            is filtered to the caller's resolved domain, so a brand-X admin cannot rearm
            a brand-Y suspension by guessing its source tag. SUPERADMIN clears matching
            rows in every brand.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Clears matching rows in own brand only</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Clears matching rows across all brands</td></tr>
            </table>

            <p>Returns the count of rows cleared (0 if no active row matched the
            source tag in the caller's domain).
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Count of cleared rows returned (Long). 0 when no active row matched "
                + "the source tag in the caller's domain."),
        @ApiResponse(responseCode = "400",
            description = "source is blank or exceeds 1 024 characters."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while stamping cleared_at. Check server logs.")
    })
    @PostMapping("/clear-source")
    public Mono<Long> clearSource(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ClearSourceRequest req) {
        // Domain-scoped variant: threads the caller's resolved PrincipalDomain so the
        // service applies the brand predicate. The back-compat un-scoped
        // clearScopeBySource(source) is NOT called from here.
        return overrides.clearScopeBySource(req.source(), PrincipalDomain.resolve(jwt, domains));
    }
}
