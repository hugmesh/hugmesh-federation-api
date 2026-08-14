package net.hugmesh.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import net.hugmesh.federation.model.CapabilityDto;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.commons.security.PrincipalDomain;

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
 *
 * <p><b>Caller-role access matrix</b> (enforced in the QUERY via the domain predicate,
 * not in spoofable code):
 * <pre>
 * Caller                       Repository method used                    Scope
 * ---------------------------- ----------------------------------------- ---------------------
 * Anonymous (no JWT)           findByDomainAndKindNot("default", ...)    default brand only
 * ROLE_USER / MOD / ADMIN      findByDomainAndKindNot(scope.domain(), .) own brand only
 * ROLE_SUPERADMIN              findByKindNot(...)                        all brands
 * (all callers)                fragment kind always excluded              no vanity slugs
 * </pre>
 *
 * @see net.hugmesh.federation.controller.CapabilityController
 * @see FederationModuleRepository
 * @see CapabilityDto
 * @see net.hugmesh.federation.model.FederationModule
 * @see ManifestService
 * @see PrincipalDomain
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

    // ----- Capability Reads -----

    /**
     * Back-compat overload: renders the {@code "default"} domain's public capability
     * list, equivalent to calling {@link #capabilities(PrincipalDomain)} with
     * {@code PrincipalDomain.forDomain("default")}. Retained for callers and tests
     * that have no {@link PrincipalDomain} in hand (the anonymous / single-issuer case).
     *
     * @return a {@code Flux} of {@link CapabilityDto} for the {@code "default"} domain,
     *         fragment-excluded, ordered by slug; empty when no non-fragment modules
     *         are registered in the default domain
     * @see #capabilities(PrincipalDomain)
     */
    public Flux<CapabilityDto> capabilities() {
        return capabilities(PrincipalDomain.forDomain("default"));
    }

    /**
     * The public-safe capability list for a caller scoped to their brand — one
     * {@link CapabilityDto} per non-fragment {@code federation_modules} row in the
     * caller's domain (SUPERADMIN: all brands), ordered by slug for a stable response.
     * The {@code installed} field on each {@link CapabilityDto} is derived per row
     * ({@code enabled} and circuit-closed). The domain and {@code 'fragment'}-excluding
     * cut is enforced in the QUERY so a cross-brand row or a {@code profile-<username>}
     * vanity slug is NEVER returned.
     *
     * @param scope the caller's domain context; {@code null} resolves to {@code "default"}
     *              (the anonymous public-read case); a {@code superadmin()} scope runs
     *              the un-pinned finder across all brands
     * @return a {@code Flux} of {@link CapabilityDto} for the caller's domain (or all
     *         brands for SUPERADMIN), fragment-excluded, ordered by slug; empty when no
     *         matching non-fragment modules are registered
     * @see FederationModuleRepository#findByDomainAndKindNot(String, String)
     * @see FederationModuleRepository#findByKindNot(String)
     * @see CapabilityDto#from(net.hugmesh.federation.model.FederationModule)
     */
    public Flux<CapabilityDto> capabilities(PrincipalDomain scope) {
        Flux<net.hugmesh.federation.model.FederationModule> rows =
                (scope != null && scope.superadmin())
                        ? repo.findByKindNot(FRAGMENT_KIND)
                        : repo.findByDomainAndKindNot(domainOf(scope), FRAGMENT_KIND);
        return rows
                .map(CapabilityDto::from)
                .sort((a, b) -> a.slug().compareTo(b.slug()));
    }

    /**
     * The domain to pin the query to: the caller's domain from {@code scope}, or
     * {@code "default"} when no scope is supplied (anonymous public read). Never
     * {@code null} — a per-domain scope always carries a domain string (a failed
     * resolve produces {@code NO_DOMAIN}, which matches nothing in the database).
     *
     * @param scope the caller's domain context; may be {@code null} for anonymous callers
     * @return the domain string to use as a query predicate
     */
    private static String domainOf(PrincipalDomain scope) {
        return scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }
}
