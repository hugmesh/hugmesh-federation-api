package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.service.OverrideService;

/**
 * The kill-switch / federation-override surface. ROLE_ADMIN only. Applying an
 * override mutates the targeted module's manifest read-path fields (circuit_state
 * / enabled) so it takes effect on the next manifest render, AND records the
 * override audit row.
 */
@Tag(name = "Override", description = "Federation kill-switch: circuit-break / unpublish / remove a module. ROLE_ADMIN required.")
@RestController
@RequestMapping("/api/federation/overrides")
@PreAuthorize("hasRole('ADMIN')")
public class OverrideController {

    private final OverrideService overrides;

    public OverrideController(OverrideService overrides) {
        this.overrides = overrides;
    }

    public record ApplyRequest(String moduleSlug, String scope, String scopeValue, String action) {}

    public record ClearScopeRequest(String scope, String target) {}

    @Operation(summary = "List applied overrides (audit trail).")
    @GetMapping
    public Flux<FederationOverride> list() {
        return overrides.list();
    }

    @Operation(
        summary = "Apply an override (kill-switch).",
        description = """
            action = circuit-break | unpublish | remove; scope = all | role | user.
            Mutates the targeted module (circuit_state / enabled, or hard-delete)
            and records the override row. Takes effect on the next manifest render.
            """)
    @PostMapping
    public Mono<FederationOverride> apply(@AuthenticationPrincipal Jwt jwt, @RequestBody ApplyRequest req) {
        return overrides.apply(req.moduleSlug(), req.scope(), req.scopeValue(), req.action(), jwt.getSubject());
    }

    @Operation(summary = "Re-arm a circuit-broken / unpublished module (admin recovery).")
    @PostMapping("/{moduleSlug}/rearm")
    public Mono<FederationModule> rearm(@PathVariable String moduleSlug) {
        return overrides.rearm(moduleSlug);
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
    public Mono<Long> clearScope(@RequestBody ClearScopeRequest req) {
        return overrides.clearScope(req.scope(), req.target());
    }
}
