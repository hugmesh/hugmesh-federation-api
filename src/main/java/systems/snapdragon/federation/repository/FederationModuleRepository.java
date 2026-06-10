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

    /**
     * The VANITY-RESOLVE finder. Returns the single module for a public profile
     * fragment iff it is serveable: matched by its deterministic slug
     * ({@code profile-<username>}), {@code kind='fragment'}, {@code visibility='public'},
     * {@code enabled=true}, and {@code circuit_state='closed'}. The DB-side
     * predicate guarantees an internal / disabled / circuit-broken fragment is
     * NEVER returned to the public vanity read path — there is no code path that
     * can leak a non-public fragment through this finder. Mono because the slug is
     * unique (one row max).
     */
    Mono<FederationModule> findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
            String slug, String kind, String visibility, String circuitState);
}
