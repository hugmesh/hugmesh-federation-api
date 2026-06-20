package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.CapabilityDto;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.commons.security.PrincipalDomain;

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
 * <p>It lists every registry row that is NOT a per-user vanity fragment, NOT just
 * the enabled/closed/public ones the manifest serves: a registered-but-disabled or
 * circuit-broken OPTIONAL service must still be reported (as
 * {@code installed=false}) so the host greys it out by STATE, while a never-
 * registered service is absent from the list so the host greys it out by ABSENCE.
 * Each row is projected to {@link CapabilityDto} — a narrow public-safe shape
 * (slug + installed + mountAt + requiresRole only); no internal locator/detail is
 * surfaced.
 *
 * <p><b>DOMAIN-scoped + fragment-excluded (cross-tenant disclosure fix).</b> The
 * row stream is the per-domain, {@code 'fragment'}-excluding finder — NOT the
 * inherited unscoped {@code findAll()} (which would leak EVERY brand's
 * {@code federation_modules} rows, including the deterministic
 * {@code profile-<username>} vanity slugs, turning a {@code permitAll} endpoint into
 * a cross-brand username/registry enumeration oracle that the vanity / username
 * surfaces otherwise lock down). The cut mirrors {@link ManifestService}'s tiers:
 *
 * <ul>
 *   <li><b>PER-DOMAIN</b> (the common case; anonymous resolves to {@code "default"})
 *       — pinned to {@code scope.domain()} via
 *       {@link FederationModuleRepository#findByDomainAndKindNot}, so a brand-X
 *       caller's capability list never reveals brand-Y's registered services.</li>
 *   <li><b>SUPERADMIN</b> ({@code scope.superadmin()}) — the un-pinned
 *       {@link FederationModuleRepository#findByKindNot} runs (all brands), still
 *       fragment-excluded.</li>
 * </ul>
 *
 * <p>Profile fragments ({@code kind='fragment'}, slug {@code profile-<username>})
 * are excluded in BOTH tiers — they are per-user vanity cards, never an OPTIONAL
 * platform service the host greys out, and their slugs are an enumeration oracle.
 * Always rendered from Postgres; no cache (this is a cheap, small projection and
 * must reflect install-state changes immediately so the host greys/un-greys without
 * staleness).
 */
@Service
public class CapabilityService {

    /** Per-user vanity profile fragments ({@code profile-<username>}) are EXCLUDED
     *  from the public capability projection — they are not OPTIONAL platform
     *  services and their slugs are a username enumeration oracle. */
    static final String FRAGMENT_KIND = "fragment";

    private final FederationModuleRepository repo;

    public CapabilityService(FederationModuleRepository repo) {
        this.repo = repo;
    }

    /**
     * Back-compat render: a caller with no domain context renders the
     * {@code "default"} domain's public capability list (the anonymous / single-issuer
     * behaviour). Retained for callers/tests that have no {@link PrincipalDomain} in hand.
     */
    public Flux<CapabilityDto> capabilities() {
        return capabilities(PrincipalDomain.forDomain("default"));
    }

    /**
     * The public-safe capability list for a caller scoped to their brand/domain — one
     * {@link CapabilityDto} per non-fragment registry row in that domain (SUPERADMIN:
     * all brands), ordered by slug for a stable response. {@code installed} is derived
     * per row (enabled + circuit-closed). The DOMAIN + {@code 'fragment'}-excluding cut
     * is enforced in the QUERY (not in spoofable code), so a cross-brand row or a
     * {@code profile-<username>} vanity slug is NEVER returned.
     */
    public Flux<CapabilityDto> capabilities(PrincipalDomain scope) {
        Flux<systems.snapdragon.federation.model.FederationModule> rows =
                (scope != null && scope.superadmin())
                        ? repo.findByKindNot(FRAGMENT_KIND)
                        : repo.findByDomainAndKindNot(domainOf(scope), FRAGMENT_KIND);
        return rows
                .map(CapabilityDto::from)
                .sort((a, b) -> a.slug().compareTo(b.slug()));
    }

    /** The domain to pin the query to: the caller's domain, or {@code "default"} when
     *  no scope is supplied (anonymous public read). Never null — a per-domain scope
     *  always carries a domain (failed resolve => NO_DOMAIN, matches nothing). */
    private static String domainOf(PrincipalDomain scope) {
        return scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }
}
