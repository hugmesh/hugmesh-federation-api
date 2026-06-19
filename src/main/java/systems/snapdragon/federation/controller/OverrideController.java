package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.security.DomainRegistry;
import systems.snapdragon.federation.security.DomainScope;
import systems.snapdragon.federation.service.OverrideService;
import systems.snapdragon.federation.web.ValidationPatterns;

/**
 * The kill-switch / federation-override surface. ROLE_ADMIN only. Applying an
 * override mutates the targeted module's manifest read-path fields (circuit_state
 * / enabled) so it takes effect on the next manifest render, AND records the
 * override audit row.
 */
@Tag(name = "Override", description = "Federation kill-switch: circuit-break / unpublish / remove a module. ROLE_ADMIN required.")
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

    /**
     * Apply-override body. {@code moduleSlug} is the targeted module (a real
     * federation_modules slug — DNS-label form); {@code scope}/{@code action}
     * mirror the 018 CHECK vocabularies ({@code OverrideService.isScope}/isAction),
     * so a bad value is a 400 here before the service / DB. {@code scopeValue} is
     * the optional scope key (userId for user, role name for role; null for all).
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

    public record ClearScopeRequest(
            @NotBlank(message = "scope is required")
            @Pattern(regexp = ValidationPatterns.OVERRIDE_SCOPE, message = "scope must be all|role|user")
            String scope,
            @Size(max = 1024, message = "target must be at most 1024 chars") String target) {}

    /**
     * Clear-by-source body. {@code source} is the SOURCE tag a scope override was
     * written with (e.g. {@code 'access_suspension:<id>'}); the matching active row(s)
     * are rearmed — but ONLY within the caller's domain (see {@link #clearSource}).
     */
    public record ClearSourceRequest(
            @NotBlank(message = "source is required")
            @Size(max = 1024, message = "source must be at most 1024 chars") String source) {}

    @Operation(summary = "List applied overrides in the caller's domain (SUPERADMIN: all).")
    @GetMapping
    public Flux<FederationOverride> list(@AuthenticationPrincipal Jwt jwt) {
        return overrides.list(DomainScope.resolve(jwt, domains));
    }

    @Operation(
        summary = "Apply an override (kill-switch).",
        description = """
            action = circuit-break | unpublish | remove; scope = all | role | user.
            Mutates the targeted module (circuit_state / enabled, or hard-delete)
            and records the override row. Takes effect on the next manifest render.
            """)
    @PostMapping
    public Mono<FederationOverride> apply(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ApplyRequest req) {
        return overrides.apply(req.moduleSlug(), req.scope(), req.scopeValue(), req.action(),
                jwt.getSubject(), DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Re-arm a circuit-broken / unpublished module (admin recovery; scoped to caller's domain).")
    @PostMapping("/{moduleSlug}/rearm")
    public Mono<FederationModule> rearm(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid moduleSlug") String moduleSlug) {
        return overrides.rearm(moduleSlug, DomainScope.resolve(jwt, domains));
    }

    @Operation(
        summary = "Clear (re-arm) an active scope override.",
        description = """
            Rearms an active scope=all|user|role kill: stamps cleared_at on the
            matching active federation_override row(s) so the manifest read path
            stops suppressing the affected modules (they return on the next
            render). target = the scope_value (userId for 'user', role name for
            'role'); omit/null for 'all'. Returns the count of rows cleared.
            """)
    @PostMapping("/clear")
    public Mono<Long> clearScope(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ClearScopeRequest req) {
        return overrides.clearScope(req.scope(), req.target(), DomainScope.resolve(jwt, domains));
    }

    @Operation(
        summary = "Clear (re-arm) the scope override(s) created by a specific SOURCE.",
        description = """
            Stamps cleared_at on every ACTIVE federation_override row whose reason
            equals the given source (e.g. 'access_suspension:<id>'), so the manifest
            read path stops suppressing the affected owner's modules (they return on
            the next render). This is the suspension-clear (rebuild) path.

            DOMAIN-scoped: a per-domain admin rearms ONLY rows in their own brand —
            the matched set is filtered to the caller's resolved domain, so a brand-X
            admin can never rearm a brand-Y suspension by guessing its source tag.
            SUPERADMIN clears matching rows in every brand. Returns the count cleared.
            """)
    @PostMapping("/clear-source")
    public Mono<Long> clearSource(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ClearSourceRequest req) {
        return overrides.clearScopeBySource(req.source(), DomainScope.resolve(jwt, domains));
    }
}
