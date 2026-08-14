package net.hugmesh.federation.repository;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.model.SystemFinding;

/**
 * Reactive (R2DBC) store for the system-generated moderation findings
 * ({@code system_findings}). Domain-scoped finders mirror
 * {@link ModerationRequestRepository}: a per-domain mod sees ONLY their own brand's
 * findings; SUPERADMIN uses the un-pinned variants.
 */
public interface SystemFindingRepository extends ReactiveCrudRepository<SystemFinding, Long> {

    Flux<SystemFinding> findAllByOrderByTsDesc();

    Flux<SystemFinding> findByStatusOrderByTsDesc(String status);

    /** DOMAIN-scoped findings list (per-domain mod view). */
    Flux<SystemFinding> findByDomainOrderByTsDesc(String domain);

    /** DOMAIN-scoped findings list by review status. */
    Flux<SystemFinding> findByStatusAndDomainOrderByTsDesc(String status, String domain);

    /** DOMAIN-scoped single-finding lookup: a cross-domain id resolves to EMPTY → 404,
     *  so a per-domain mod can never resolve another brand's finding. SUPERADMIN uses
     *  the inherited {@link #findById(Object)}. */
    Mono<SystemFinding> findByIdAndDomain(Long id, String domain);

    // ----- Resolved-findings RECONCILE read (moderation → activation loop) -----

    /**
     * The shared WHERE-clause of the reconcile read, held as a {@code static final String}
     * per the data-access standard (no inline {@code @Query} literals; no concatenated
     * user input — the {@code status IN} set is a fixed terminal-status allow-list).
     *
     * <p>Selects only RESOLVED findings the reconciler can act on:
     * <ul>
     *   <li>{@code status IN ('actioned','dismissed')} — terminal outcomes set by resolve;
     *       {@code held} (still in review) is excluded;</li>
     *   <li>{@code surface = :surface} — the caller scopes to one surface
     *       ({@code character-part} / {@code character-sticker});</li>
     *   <li>{@code id > :sinceId} — the cursor/watermark: a strict {@code >} so a re-poll
     *       with the last-seen id never re-emits it;</li>
     *   <li>{@code subject_ref IS NOT NULL} — only findings that name an EXACT source row
     *       can be mapped back + pushed; the surface-level avatar/profile path (NULL
     *       subjectRef) is excluded.</li>
     * </ul>
     * {@code ORDER BY id ASC} makes the id a monotonic watermark; {@code LIMIT :limit}
     * caps the page. Backed by {@code idx_system_findings_surface_status} (changeset 037).
     */
    String RESOLVED_RECONCILE_WHERE =
            "status IN ('actioned','dismissed') AND surface = :surface "
            + "AND id > :sinceId AND subject_ref IS NOT NULL";

    /** Cross-domain reconcile page (the platform reconciler / SUPERADMIN). */
    String FIND_RESOLVED_FOR_RECONCILE =
            "SELECT * FROM system_findings WHERE " + RESOLVED_RECONCILE_WHERE
            + " ORDER BY id ASC LIMIT :limit";

    /** DOMAIN-pinned reconcile page (a per-domain ADMIN reconciler). */
    String FIND_RESOLVED_FOR_RECONCILE_IN_DOMAIN =
            "SELECT * FROM system_findings WHERE " + RESOLVED_RECONCILE_WHERE
            + " AND domain = :domain ORDER BY id ASC LIMIT :limit";

    /**
     * CROSS-DOMAIN resolved-findings page for the moderation → activation reconciler:
     * resolved ({@code actioned}/{@code dismissed}), {@code surface}-scoped,
     * {@code id > sinceId} cursor, {@code subject_ref} present, id-ASC, capped at
     * {@code limit}. The cross-domain variant is for the platform reconciler (a SERVICE
     * token) / SUPERADMIN; a per-domain ADMIN uses {@link #findResolvedForReconcileInDomain}.
     */
    @Query(FIND_RESOLVED_FOR_RECONCILE)
    Flux<SystemFinding> findResolvedForReconcile(@Param("surface") String surface,
                                                 @Param("sinceId") long sinceId,
                                                 @Param("limit") int limit);

    /**
     * DOMAIN-pinned variant of {@link #findResolvedForReconcile}: identical predicate +
     * cursor + ordering + cap, additionally restricted to one {@code domain} so a
     * per-domain reconciler can never read another brand's resolved findings.
     */
    @Query(FIND_RESOLVED_FOR_RECONCILE_IN_DOMAIN)
    Flux<SystemFinding> findResolvedForReconcileInDomain(@Param("surface") String surface,
                                                         @Param("sinceId") long sinceId,
                                                         @Param("domain") String domain,
                                                         @Param("limit") int limit);
}
