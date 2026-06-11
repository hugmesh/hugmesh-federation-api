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

    /**
     * Best-effort DELETE of the cached manifest row so the next read is a forced
     * cache-miss that re-renders from Postgres. Called on a scope=user mutation
     * (the access-suspension profile-ban path) so a just-banned profile's modules
     * can NEVER be served from a stale cached manifest — the durable
     * federation_override row already removes them from the Postgres render, and
     * dropping the cache guarantees the next poll reflects it immediately.
     *
     * <p>Best-effort like {@link #put}: a failure (unconfigured / unreachable
     * cache) must NEVER block the ban write path — the authoritative Postgres read
     * already excludes the banned modules, so a failed invalidate only means a
     * bounded staleness until the cache TTL / next put, never an incorrect serve.
     */
    Mono<Void> invalidate();

    /** Implementation name for log lines ({@code cassandra} / {@code noop}). */
    String label();
}
