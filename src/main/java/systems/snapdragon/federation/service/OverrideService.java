package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * The kill-switch. Applies a {@link FederationOverride} to the targeted module
 * AND records the override row for audit. The override verb maps to a mutation
 * of the {@code federation_modules} read-path fields, so the change takes effect
 * on the very next manifest render (no redeploy):
 *
 * <ul>
 *   <li>{@code circuit-break} -> {@code circuit_state='open'} (manifest drops it)</li>
 *   <li>{@code unpublish}     -> {@code enabled=false}</li>
 *   <li>{@code remove}        -> hard-delete the module</li>
 * </ul>
 *
 * <p>An override has TWO effects, both audited on the one row:
 *
 * <ul>
 *   <li><b>Per-module mutation</b> (unchanged): the targeted {@code moduleSlug}'s
 *       read-path fields are mutated (circuit_state / enabled, or hard-delete), so
 *       the manifest's enabled+circuit DB finder drops it on the next render.</li>
 *   <li><b>Scope-override active row</b> (changeset 014): the row's
 *       {@code scope}/{@code target} describe WHO the kill applies to
 *       ({@code all} = everything; {@code user} = an owner's modules;
 *       {@code role} = modules declaring that required role). While
 *       {@code cleared_at IS NULL} the row is ACTIVE and
 *       {@link ManifestService} applies it across the whole catalogue at render
 *       time. {@link #clearScope} stamps {@code cleared_at} to rearm.</li>
 * </ul>
 *
 * <p>Audit-format note (intentional change): for scope=user|role the row's
 * {@code target} now carries the SCOPE VALUE (userId / role name) so the read path
 * has a clean key to match on; for scope=all {@code target} is NULL. Genuine
 * per-module intent still mutates the named module. This replaces the previous
 * {@code "slug@scopeValue"} fold (see README).
 */
@Service
public class OverrideService {

    private final FederationOverrideRepository overrides;
    private final FederationModuleRepository modules;

    public OverrideService(FederationOverrideRepository overrides, FederationModuleRepository modules) {
        this.overrides = overrides;
        this.modules = modules;
    }

    public Flux<FederationOverride> list() {
        return overrides.findAllByOrderByTsDesc();
    }

    /**
     * Apply an override against a module slug. {@code setBy} is the admin's
     * Casdoor subject. Records the audit row then mutates the module.
     */
    public Mono<FederationOverride> apply(String moduleSlug, String scope, String scopeValue,
                                          String action, String setBy) {
        if (!isAction(action)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST,
                    "action must be circuit-break | unpublish | remove"));
        }
        if (!isScope(scope)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "scope must be all | role | user"));
        }
        return modules.findBySlug(moduleSlug)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + moduleSlug)))
                .flatMap(m -> applyToModule(m, action)
                        .then(recordOverride(moduleSlug, scope, scopeValue, action, setBy)));
    }

    private Mono<?> applyToModule(FederationModule m, String action) {
        switch (action) {
            case "circuit-break":
                m.setCircuitState("open");
                m.setUpdatedAt(Instant.now());
                return modules.save(m);
            case "unpublish":
                m.setEnabled(false);
                m.setUpdatedAt(Instant.now());
                return modules.save(m);
            case "remove":
                return modules.delete(m);
            default:
                return Mono.error(new ResponseStatusException(BAD_REQUEST, "unknown action: " + action));
        }
    }

    private Mono<FederationOverride> recordOverride(String moduleSlug, String scope, String scopeValue,
                                                    String action, String setBy) {
        FederationOverride o = new FederationOverride();
        o.setScope(scope);
        // The active scope-override row's target is the read-path match KEY:
        //   scope=all  -> NULL (matches every module — global kill)
        //   scope=user -> the owner userId (matched vs module.owner_user_id)
        //   scope=role -> the role name  (matched vs module metadata requiresRole)
        // (the named moduleSlug is still mutated above for genuine per-slug intent).
        o.setTarget(scopeForTarget(scope, moduleSlug, scopeValue));
        o.setAction(action);
        o.setSetBy(setBy);
        o.setTs(Instant.now());
        // clearedAt stays NULL => the scope override is ACTIVE (changeset 014).
        return overrides.save(o);
    }

    /** Decision-1 target rule: NULL for 'all'; the scope_value for user/role; the
     *  slug only when no scope_value was given (genuine per-slug intent). */
    private static String scopeForTarget(String scope, String moduleSlug, String scopeValue) {
        if ("all".equals(scope)) {
            return null;
        }
        return (scopeValue == null || scopeValue.isBlank()) ? moduleSlug : scopeValue;
    }

    /** Re-arm a circuit-broken module (admin recovery): flip circuit_state back to closed. */
    public Mono<FederationModule> rearm(String moduleSlug) {
        return modules.findBySlug(moduleSlug)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + moduleSlug)))
                .flatMap(m -> {
                    m.setCircuitState("closed");
                    m.setEnabled(true);
                    m.setUpdatedAt(Instant.now());
                    return modules.save(m);
                });
    }

    /**
     * Rearm a SCOPE override (admin recovery for an all/user/role kill): stamp
     * {@code cleared_at} on every matching active row so the manifest read path
     * stops applying it (the suppressed modules return to the next render). For
     * scope=all the target is NULL and we key on scope alone.
     *
     * <p>Returns the number of rows cleared. Scope kills are render-time only
     * (modules are never mutated), so clearing the row is sufficient to restore;
     * per-module recovery still uses {@link #rearm(String)}.
     */
    public Mono<Long> clearScope(String scope, String target) {
        if (!isScope(scope)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "scope must be all | role | user"));
        }
        Flux<FederationOverride> active = "all".equals(scope)
                ? overrides.findByScopeAndClearedAtIsNull("all")
                : overrides.findByScopeAndTargetAndClearedAtIsNull(scope, target);
        Instant now = Instant.now();
        return active
                .flatMap(o -> {
                    o.setClearedAt(now);
                    return overrides.save(o);
                })
                .count();
    }

    private static boolean isAction(String a) {
        return "circuit-break".equals(a) || "unpublish".equals(a) || "remove".equals(a);
    }

    private static boolean isScope(String s) {
        return "all".equals(s) || "role".equals(s) || "user".equals(s);
    }
}
