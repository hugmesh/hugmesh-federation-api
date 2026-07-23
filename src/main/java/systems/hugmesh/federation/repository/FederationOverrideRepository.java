package systems.hugmesh.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import systems.hugmesh.federation.model.FederationOverride;

import java.util.Collection;

/**
 * Reactive (R2DBC) store for the kill-switch / scoped-action audit
 * ({@code federation_override}).
 */
public interface FederationOverrideRepository extends ReactiveCrudRepository<FederationOverride, Long> {

    Flux<FederationOverride> findAllByOrderByTsDesc();

    /** DOMAIN-scoped override audit list (multi-tenancy, changeset 026): the same
     *  ts-desc audit trail, pinned to the principal's {@code domain}. A per-domain
     *  admin sees ONLY their own brand's overrides; SUPERADMIN uses the un-pinned
     *  {@link #findAllByOrderByTsDesc()}. */
    Flux<FederationOverride> findByDomainOrderByTsDesc(String domain);

    Flux<FederationOverride> findByTarget(String target);

    /**
     * The manifest read path's active scope-override set: rows whose {@code scope}
     * is one of {@code all|user|role} that have NOT been cleared/rearmed
     * ({@code cleared_at IS NULL}). Loaded once per render, applied in code.
     * SUPERADMIN tier uses this (active scope rows across ALL domains).
     */
    Flux<FederationOverride> findByScopeInAndClearedAtIsNull(Collection<String> scopes);

    /**
     * DOMAIN-scoped active scope-override set (multi-tenancy, changeset 026): the
     * same active {@code all|user|role} rows ({@code cleared_at IS NULL}), pinned to
     * the caller's {@code domain}. The per-domain manifest render applies ONLY its
     * own brand's kill-switch scope rows, so a brand-X scope=all kill never blanks a
     * brand-Y caller's manifest.
     */
    Flux<FederationOverride> findByScopeInAndClearedAtIsNullAndDomain(
            Collection<String> scopes, String domain);

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
     *
     * <p>SUPERADMIN tier uses this (active source rows across ALL domains).
     */
    Flux<FederationOverride> findByReasonAndClearedAtIsNull(String reason);

    /**
     * DOMAIN-scoped source-override clear (multi-tenancy): the same
     * {@code reason}-pinned active row set ({@code cleared_at IS NULL}), further
     * pinned to a single {@code domain}. A per-domain ADMIN can clear ONLY the
     * override row(s) their own brand created — never another brand's source-tagged
     * row (cross-domain rearm is denied by returning empty, not a 403, so the caller
     * can never guess foreign domain identifiers from the response count).
     */
    Flux<FederationOverride> findByReasonAndClearedAtIsNullAndDomain(String reason, String domain);
}
