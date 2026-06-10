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

    Mono<UserModule> findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(String slug);

    /**
     * The CALLER'S OWN current (non-superseded) bundle for a slug — the owner-scoped
     * read/delete anchor. Owner = JWT subject; an admin override is handled in the
     * service by falling back to the slug-only active finder above.
     */
    Mono<UserModule> findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
            String slug, String ownerUserId);

    Mono<UserModule> findByContentHash(String contentHash);
}
