package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationManifestDto.FederationRemoteDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;

import java.time.Instant;
import java.util.Set;

/**
 * The federation manifest read path — the platform keystone.
 *
 * <p>Lifted from the games {@code FederationController.manifest()}
 * (findAllByEnabledTrue -> DTO -> {generatedAt, remotes}) and extended with the
 * three platform filters applied IN CODE against the caller (so the same DB rows
 * serve every audience, filtered per request):
 *
 * <ul>
 *   <li><b>enabled</b>  — DB-side ({@code findAllByEnabledTrue...}); an
 *       unpublish override flips {@code enabled=false}.</li>
 *   <li><b>circuit-state</b> — only {@code circuit_state='closed'} rows ship;
 *       a circuit-break override flips it to {@code 'open'} so the remote drops
 *       from the manifest without a redeploy (kill-switch).</li>
 *   <li><b>visibility / role</b> — {@code visibility='public'} rows are visible
 *       to everyone; {@code visibility='internal'} rows only to callers holding
 *       {@code ROLE_ADMIN} (or {@code ROLE_INTERNAL}). The host enforces
 *       per-remote route access too; this is the catalog-level cut.</li>
 * </ul>
 *
 * <p>The rendered manifest is write-through cached (best-effort) so the
 * remote-fragment pods / edge can poll it; a cache miss / failure always renders
 * from Postgres.
 */
@Service
public class ManifestService {

    private final FederationModuleRepository repo;
    private final ManifestCache cache;

    public ManifestService(FederationModuleRepository repo, ManifestCache cache) {
        this.repo = repo;
        this.cache = cache;
    }

    /**
     * Render the manifest for a caller with the given authorities. {@code admin}
     * controls whether {@code internal}-visibility remotes are included.
     *
     * <p>Always rendered from Postgres for the authoritative, per-caller-filtered
     * result; the cache is written through on the (unfiltered-superset) public
     * render so it never leaks internal rows to an anonymous poller.
     */
    public Mono<FederationManifestDto> render(Set<String> authorities) {
        boolean canSeeInternal = authorities != null
                && (authorities.contains("ROLE_ADMIN") || authorities.contains("ROLE_INTERNAL"));
        return repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed")
                .filter(m -> isVisibleTo(m, canSeeInternal))
                .map(FederationRemoteDto::from)
                .collectList()
                .map(remotes -> new FederationManifestDto(Instant.now().toString(), remotes))
                .flatMap(manifest -> {
                    // Write-through ONLY the public-safe view (no internal rows)
                    // so a cache poller without a token never sees internal
                    // remotes. Best-effort; failure is swallowed in the cache.
                    if (!canSeeInternal) {
                        return cache.put(manifest).thenReturn(manifest);
                    }
                    return Mono.just(manifest);
                });
    }

    /** Visibility/role cut: public to all; internal only to admin/internal callers. */
    static boolean isVisibleTo(FederationModule m, boolean canSeeInternal) {
        String v = m.getVisibility() == null ? "public" : m.getVisibility();
        if ("internal".equalsIgnoreCase(v)) {
            return canSeeInternal;
        }
        return true; // 'public' (or any other value) is visible to everyone
    }

    /** All enabled+closed rows as entities (used by tests + admin tooling). */
    public Flux<FederationModule> activeModules() {
        return repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed");
    }
}
