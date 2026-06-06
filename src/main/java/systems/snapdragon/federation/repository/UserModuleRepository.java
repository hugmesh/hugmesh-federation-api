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

    Mono<UserModule> findByContentHash(String contentHash);
}
