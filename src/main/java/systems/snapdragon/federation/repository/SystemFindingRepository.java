package systems.snapdragon.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.SystemFinding;

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
}
