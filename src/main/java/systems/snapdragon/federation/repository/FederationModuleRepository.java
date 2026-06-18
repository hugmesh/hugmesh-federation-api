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
     *  drops circuit-open remotes). SUPERADMIN tier uses this (all domains). */
    Flux<FederationModule> findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(String circuitState);

    /**
     * DOMAIN-scoped manifest read path (multi-tenancy, changeset 026): the same
     * enabled + circuit-closed, kind-then-slug ordered finder, additionally pinned to
     * the caller's {@code domain}. A per-domain principal's manifest therefore lists
     * ONLY their own brand's remotes; the SUPERADMIN tier uses the un-pinned finder
     * above to see every domain's remotes. The DB-side predicate guarantees a
     * cross-domain remote is NEVER returned to a domain-scoped caller — the per-domain
     * CUT is enforced in the query, not (spoofable) in code.
     */
    Flux<FederationModule> findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(
            String circuitState, String domain);

    Mono<FederationModule> findBySlug(String slug);

    /**
     * DOMAIN-scoped slug lookup (multi-tenancy, changeset 026): the same single-row
     * slug finder, but additionally pinned to the principal's {@code domain}. The
     * registry CRUD / kill-switch paths use this so a per-domain admin can only
     * read/mutate a module IN THEIR OWN domain — a slug that exists in another
     * brand's domain returns EMPTY (404), never the cross-domain row. SUPERADMIN
     * bypasses this and uses {@link #findBySlug(String)} (no domain predicate).
     */
    Mono<FederationModule> findBySlugAndDomain(String slug, String domain);

    /** DOMAIN-scoped admin listing (multi-tenancy, changeset 026): every registry
     *  row in the principal's domain. SUPERADMIN uses the inherited {@code findAll()}
     *  (all domains). */
    Flux<FederationModule> findByDomain(String domain);

    /**
     * The PUBLIC capability-projection read path's finder: every registry row in the
     * caller's {@code domain} EXCEPT a given {@code kind} (the
     * {@code 'fragment'}-excluding cut). The capability list greys-out OPTIONAL
     * platform services (forum / mastodon / matrix / games — {@code remote-shell}
     * kind) and must NEVER surface per-user {@code profile-<username>} vanity
     * fragments ({@code kind='fragment'}) — those would be a username enumeration
     * oracle the vanity / username surfaces lock down. Pinning to {@code domain} also
     * stops a brand-X anonymous caller from learning brand-Y's registered services.
     * Mirrors {@link ModuleRegistryService}'s per-domain cut; SUPERADMIN uses
     * {@link #findByKindNot(String)} (un-pinned, all brands, still fragment-excluded).
     */
    Flux<FederationModule> findByDomainAndKindNot(String domain, String kind);

    /**
     * SUPERADMIN tier of the capability projection: every registry row across ALL
     * brands EXCEPT a given {@code kind} (the {@code 'fragment'}-excluding cut). No
     * domain predicate (the cross-domain infra role sees every brand), but profile
     * fragments are STILL excluded so the public-safe shape never carries a
     * {@code profile-<username>} slug regardless of caller.
     */
    Flux<FederationModule> findByKindNot(String kind);

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
