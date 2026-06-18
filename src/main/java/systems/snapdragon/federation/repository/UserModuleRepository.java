package systems.snapdragon.federation.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.UserModule;

/**
 * Reactive (R2DBC) store for per-user bundle uploads ({@code user_modules}).
 * Mirrors the games {@code GameUploadRepository}: active (non-superseded) rows
 * per slug, owner-scoped listing, and content-hash lookup (the sync key the
 * remote-fragment pods fetch by).
 */
public interface UserModuleRepository extends ReactiveCrudRepository<UserModule, Long> {

    Flux<UserModule> findByOwnerUserIdOrderByCreatedAtDesc(String ownerUserId);

    Flux<UserModule> findBySlugOrderByCreatedAtDesc(String slug);

    /**
     * DOMAIN-scoped slug listing (multi-tenancy, changeset 035): the same
     * created-at-desc version history for a slug, additionally pinned to the caller's
     * {@code domain}. The bundle METADATA read ({@code /bundles/slug/{slug}}) uses
     * this so a per-domain caller only ever sees their OWN brand's bundle versions —
     * a slug whose rows live in another brand returns EMPTY, never the cross-domain
     * metadata. SUPERADMIN uses the un-pinned {@link #findBySlugOrderByCreatedAtDesc}
     * (all brands). Mirrors the ModuleRegistryService per-domain query cut.
     */
    Flux<UserModule> findBySlugAndDomainOrderByCreatedAtDesc(String slug, String domain);

    /**
     * DOMAIN-scoped + OWNER-scoped slug listing: a per-domain NON-admin caller only
     * sees their own bundle versions for the slug (their brand AND their ownership).
     * Used by the metadata read so a non-admin never enumerates a same-brand peer's
     * bundle metadata. SUPERADMIN / admin use the broader finders above.
     */
    Flux<UserModule> findBySlugAndDomainAndOwnerUserIdOrderByCreatedAtDesc(
            String slug, String domain, String ownerUserId);

    Mono<UserModule> findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(String slug);

    /**
     * The CALLER'S OWN current (non-superseded) bundle for a slug — the owner-scoped
     * read/delete anchor. Owner = JWT subject; an admin override is handled in the
     * service by falling back to the slug-only active finder above.
     */
    Mono<UserModule> findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
            String slug, String ownerUserId);

    Mono<UserModule> findByContentHash(String contentHash);

    /**
     * DOMAIN-scoped content-hash lookup (multi-tenancy, changeset 035): the same
     * single-row content-hash finder, pinned to the caller's {@code domain}. The
     * bundle METADATA read ({@code /bundles/{contentHash}}) uses this so a per-domain
     * caller can only resolve a hash that belongs to THEIR brand — a hash registered
     * in another brand returns EMPTY (404), closing the cross-tenant metadata IDOR
     * and the content-hash -> bytes pivot. SUPERADMIN uses the un-pinned
     * {@link #findByContentHash} (all brands).
     *
     * <p>NB: the remote-fragment SYNC byte FETCH ({@code /bundles/{hash}/files/{*path}})
     * is INTENTIONALLY un-scoped (capability-by-hash) and stays on
     * {@link #findByContentHash}; only the METADATA read gains this cut.
     */
    Mono<UserModule> findByContentHashAndDomain(String contentHash, String domain);

    /**
     * DOMAIN + OWNER scoped content-hash lookup: a per-domain NON-admin caller can only
     * resolve a hash for a bundle they OWN in their brand. Keeps a non-admin from
     * pivoting a same-brand peer's content hash into that peer's bundle metadata.
     */
    Mono<UserModule> findByContentHashAndDomainAndOwnerUserId(
            String contentHash, String domain, String ownerUserId);
}
