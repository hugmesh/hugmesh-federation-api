package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.CapabilityDto;
import systems.snapdragon.federation.repository.FederationModuleRepository;

/**
 * The PUBLIC capability-projection read path behind
 * {@code GET /api/federation/capabilities}.
 *
 * <p>A thin, additive sibling of {@link ManifestService} — it is DELIBERATELY
 * separate so the manifest read path (visibility/role/scope-filtered, authed) is
 * left completely UNCHANGED. This service builds the public-safe install-state list
 * a logged-out / non-admin host uses to grey-out OPTIONAL services (forum /
 * mastodon / matrix / games) that are absent or disabled.
 *
 * <p>It lists EVERY registry row (via the inherited {@code findAll()}), NOT just
 * the enabled/closed/public ones the manifest serves: a registered-but-disabled or
 * circuit-broken OPTIONAL service must still be reported (as
 * {@code installed=false}) so the host greys it out by STATE, while a never-
 * registered service is absent from the list so the host greys it out by ABSENCE.
 * Each row is projected to {@link CapabilityDto} — a narrow public-safe shape
 * (slug + installed + mountAt + requiresRole only); no internal locator/detail is
 * surfaced. There is NO caller-dependent filtering, so the body is identical for
 * every caller and safe to expose with no JWT.
 */
@Service
public class CapabilityService {

    private final FederationModuleRepository repo;

    public CapabilityService(FederationModuleRepository repo) {
        this.repo = repo;
    }

    /**
     * The full public-safe capability list — one {@link CapabilityDto} per registry
     * row, ordered by slug for a stable response. {@code installed} is derived per
     * row (enabled + circuit-closed). Always rendered from Postgres; no cache (this
     * is a cheap, small, public projection and must reflect install-state changes
     * immediately so the host greys/un-greys without staleness).
     */
    public Flux<CapabilityDto> capabilities() {
        return repo.findAll()
                .map(CapabilityDto::from)
                .sort((a, b) -> a.slug().compareTo(b.slug()));
    }
}
