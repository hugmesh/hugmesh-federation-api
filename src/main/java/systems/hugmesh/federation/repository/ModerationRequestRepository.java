package systems.hugmesh.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.ModerationRequest;

/**
 * Reactive (R2DBC) store for the moderation workflow ({@code moderation_requests}).
 */
public interface ModerationRequestRepository extends ReactiveCrudRepository<ModerationRequest, Long> {

    Flux<ModerationRequest> findByStatusOrderByTsDesc(String status);

    Flux<ModerationRequest> findAllByOrderByTsDesc();

    /** DOMAIN-scoped moderation list (multi-tenancy, changeset 026): the same
     *  ts-desc workflow list, pinned to the principal's {@code domain}. A per-domain
     *  mod/admin sees ONLY their own brand's requests; SUPERADMIN uses the un-pinned
     *  {@link #findAllByOrderByTsDesc()}. */
    Flux<ModerationRequest> findByDomainOrderByTsDesc(String domain);

    /** DOMAIN-scoped moderation list by status (multi-tenancy, changeset 026). */
    Flux<ModerationRequest> findByStatusAndDomainOrderByTsDesc(String status, String domain);

    /**
     * DOMAIN-scoped single-request lookup (multi-tenancy, changeset 026): refer /
     * decide load the row by id pinned to the principal's {@code domain}, so a
     * per-domain mod/admin can NEVER refer or decide a request that belongs to
     * another brand (a cross-domain id returns EMPTY -> 404). SUPERADMIN bypasses
     * this and uses the inherited {@code findById(Long)}.
     */
    Mono<ModerationRequest> findByIdAndDomain(Long id, String domain);
}
