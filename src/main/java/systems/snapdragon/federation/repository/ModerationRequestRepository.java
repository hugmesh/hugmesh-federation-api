package systems.snapdragon.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.ModerationRequest;

/**
 * Reactive (R2DBC) store for the moderation workflow ({@code moderation_requests}).
 */
public interface ModerationRequestRepository extends ReactiveCrudRepository<ModerationRequest, Long> {

    Flux<ModerationRequest> findByStatusOrderByTsDesc(String status);

    Flux<ModerationRequest> findAllByOrderByTsDesc();
}
