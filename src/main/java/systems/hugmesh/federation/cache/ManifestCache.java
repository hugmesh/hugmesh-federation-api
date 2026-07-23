package systems.hugmesh.federation.cache;

import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationManifestDto;

/**
 * Write-through cache of the rendered federation manifest. The authoritative
 * source is always Postgres (R2DBC); this mirror makes the manifest visible to
 * the remote-fragment pods / edge sooner and survives a brief Postgres blip.
 *
 * <p>Every operation is best-effort: a failure (unconfigured / unreachable cache)
 * must NEVER block the manifest read path — exactly the
 * {@code CassandraRouteMirror} contract in admin-bff.
 *
 * <p><b>Per-brand cache key.</b> Every operation is keyed by {@code domain} (the
 * caller's resolved brand, e.g. {@code "default"}) so each brand's public-safe
 * manifest is cached under its OWN row — a brand-B poller can never be served
 * brand-A's cached body, and a brand-A mutation invalidates only brand-A's row.
 * {@link systems.hugmesh.federation.service.ManifestService} only ever
 * write-throughs a render that is public-safe FOR its own domain (see
 * {@code isPublicSafeRender}); the SUPERADMIN cross-domain superset is never
 * cacheable under any key.
 */
public interface ManifestCache {

    /** Best-effort write of the freshly rendered manifest for {@code domain}. Never throws. */
    Mono<Void> put(String domain, FederationManifestDto manifest);

    /**
     * Best-effort read of the cached manifest for {@code domain}, or empty when
     * absent / the cache is disabled or unreachable. The service treats an empty
     * result as a cache-miss and renders from Postgres.
     */
    Mono<FederationManifestDto> get(String domain);

    /**
     * Best-effort DELETE of the cached manifest row for {@code domain} so the next
     * read for that brand is a forced cache-miss that re-renders from Postgres.
     * Called on a scope=user mutation (the access-suspension profile-ban path) so
     * a just-banned profile's modules can NEVER be served from a stale cached
     * manifest — the durable federation_override row already removes them from
     * the Postgres render, and dropping the cache guarantees the next poll
     * reflects it immediately. Scoped to the mutation's OWN domain: banning a
     * brand-B user never touches brand-A's cached row.
     *
     * <p>Best-effort like {@link #put}: a failure (unconfigured / unreachable
     * cache) must NEVER block the ban write path — the authoritative Postgres read
     * already excludes the banned modules, so a failed invalidate only means a
     * bounded staleness until the cache TTL / next put, never an incorrect serve.
     */
    Mono<Void> invalidate(String domain);

    /** Implementation name for log lines ({@code cassandra} / {@code noop}). */
    String label();
}
