package systems.snapdragon.federation.cache;

import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationManifestDto;

/**
 * Write-through cache of the rendered federation manifest. The authoritative
 * source is always Postgres (R2DBC); this mirror makes the manifest visible to
 * the remote-fragment pods / edge sooner and survives a brief Postgres blip.
 *
 * <p>Every operation is best-effort: a failure (unconfigured / unreachable cache)
 * must NEVER block the manifest read path — exactly the
 * {@code CassandraRouteMirror} contract in admin-bff.
 */
public interface ManifestCache {

    /** Best-effort write of the freshly rendered manifest. Never throws. */
    Mono<Void> put(FederationManifestDto manifest);

    /**
     * Best-effort read of the cached manifest, or empty when absent / the cache
     * is disabled or unreachable. The service treats an empty result as a
     * cache-miss and renders from Postgres.
     */
    Mono<FederationManifestDto> get();

    /** Implementation name for log lines ({@code cassandra} / {@code noop}). */
    String label();
}
