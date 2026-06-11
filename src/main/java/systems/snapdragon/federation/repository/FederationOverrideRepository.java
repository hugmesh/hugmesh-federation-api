package systems.snapdragon.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.FederationOverride;

import java.util.Collection;

/**
 * Reactive (R2DBC) store for the kill-switch / scoped-action audit
 * ({@code federation_override}).
 */
public interface FederationOverrideRepository extends ReactiveCrudRepository<FederationOverride, Long> {

    Flux<FederationOverride> findAllByOrderByTsDesc();

    Flux<FederationOverride> findByTarget(String target);

    /**
     * The manifest read path's active scope-override set: rows whose {@code scope}
     * is one of {@code all|user|role} that have NOT been cleared/rearmed
     * ({@code cleared_at IS NULL}). Loaded once per render, applied in code.
     */
    Flux<FederationOverride> findByScopeInAndClearedAtIsNull(Collection<String> scopes);

    /**
     * The active scope=user|role override(s) for a specific {@code target}
     * (scope_value), used by {@code clearScope} to find what to rearm.
     */
    Flux<FederationOverride> findByScopeAndTargetAndClearedAtIsNull(String scope, String target);

    /**
     * The active scope=all override(s). scope=all carries a NULL target, so the
     * target-bearing finder cannot match it; this variant keys on scope alone.
     */
    Flux<FederationOverride> findByScopeAndClearedAtIsNull(String scope);

    /**
     * The active scope-override(s) created by a specific SOURCE (changeset 019),
     * e.g. {@code 'access_suspension:<id>'}. Used by
     * {@code OverrideService.clearScopeBySource} so an expiring suspension clears
     * ONLY the row(s) it wrote — never a manual admin kill (which carries a NULL /
     * different {@code reason}). Indexed on {@code reason}.
     */
    Flux<FederationOverride> findByReasonAndClearedAtIsNull(String reason);
}
