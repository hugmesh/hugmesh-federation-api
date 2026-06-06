package systems.snapdragon.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.FederationOverride;

/**
 * Reactive (R2DBC) store for the kill-switch / scoped-action audit
 * ({@code federation_override}).
 */
public interface FederationOverrideRepository extends ReactiveCrudRepository<FederationOverride, Long> {

    Flux<FederationOverride> findAllByOrderByTsDesc();

    Flux<FederationOverride> findByTarget(String target);
}
