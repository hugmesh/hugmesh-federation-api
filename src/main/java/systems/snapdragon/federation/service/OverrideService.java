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
 * <p>The override's {@code target} names the module slug to act on (the scope
 * triple — all/role/user — records WHO the action was decided against; the
 * per-role-BFF read path can layer scope filtering on top later, see README).
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
        // target carries BOTH the module slug being acted on and the scope_value;
        // we record the slug as the primary target and fold the scope_value in
        // when present so the audit row is self-describing.
        o.setTarget(scopeValue == null || scopeValue.isBlank() ? moduleSlug : moduleSlug + "@" + scopeValue);
        o.setAction(action);
        o.setSetBy(setBy);
        o.setTs(Instant.now());
        return overrides.save(o);
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

    private static boolean isAction(String a) {
        return "circuit-break".equals(a) || "unpublish".equals(a) || "remove".equals(a);
    }

    private static boolean isScope(String s) {
        return "all".equals(s) || "role".equals(s) || "user".equals(s);
    }
}
