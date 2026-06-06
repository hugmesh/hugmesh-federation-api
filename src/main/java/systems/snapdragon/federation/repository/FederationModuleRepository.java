package systems.snapdragon.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;

/**
 * Reactive (R2DBC) store for the federation registry. Mirrors the games
 * {@code FederationModuleRepository}: the manifest read path uses the
 * enabled-ordered finder; the registry CRUD + kill-switch use the slug + circuit
 * finders.
 */
public interface FederationModuleRepository extends ReactiveCrudRepository<FederationModule, Long> {

    /** The base manifest query — every enabled row, kind then slug (visibility +
     *  circuit-state filtering is applied in the service against the caller). */
    Flux<FederationModule> findAllByEnabledTrueOrderByKindAscSlugAsc();

    /** Manifest read path, narrowed to circuit-closed rows (the kill-switch
     *  drops circuit-open remotes). */
    Flux<FederationModule> findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(String circuitState);

    Mono<FederationModule> findBySlug(String slug);

    Flux<FederationModule> findByOwnerUserId(String ownerUserId);
}
