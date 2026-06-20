package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.CapabilityDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.commons.security.PrincipalDomain;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * BUG-A (cross-tenant disclosure) proof for the PUBLIC capability projection.
 *
 * <p>The endpoint {@code GET /api/federation/capabilities} is {@code permitAll}. The
 * service MUST scope its row stream to the caller's domain (anonymous => "default")
 * and EXCLUDE per-user {@code profile-<username>} vanity fragments — otherwise the
 * inherited unscoped {@code findAll()} leaks EVERY brand's {@code federation_modules}
 * rows (including the deterministic profile slugs), turning the public endpoint into a
 * cross-brand registry + username enumeration oracle.
 *
 * <p>FAIL-FIRST: against the unfixed service (which called {@code repo.findAll()}),
 * {@link #capabilities_useDomainPinnedFragmentExcludingFinder_notFindAll} fails because
 * the domain-pinned, fragment-excluding finder is never invoked (and {@code findAll}
 * IS), so the DENY assertions (no cross-brand row, no profile slug) cannot hold.
 *
 * <p>Delineated per the comprehensive test standard:
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a default-domain caller sees their own domain's
 *       non-fragment rows.</li>
 *   <li><b>CROSS-USER DENY</b> — the brand-X query never returns a brand-Y row, and
 *       the public projection never carries a {@code profile-<username>} slug.</li>
 *   <li><b>SUPERADMIN</b> — the un-pinned (all-brands) finder runs, still
 *       fragment-excluded.</li>
 * </ul>
 */
class CapabilityDomainScopeTest {

    private static FederationModule module(String slug, String kind, String domain) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind(kind);
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility("internal");
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setMetadata("{\"mountAt\":\"/x/" + slug + "\",\"requiresRole\":\"" + slug + "\"}");
        m.setDomain(domain);
        return m;
    }

    // USER-SITUATIONAL + CROSS-USER DENY: an anonymous/default-domain caller's
    // projection is built from the DOMAIN-pinned, fragment-excluding finder — so a
    // brand-Y row and a profile-<username> fragment can never surface. The finder
    // returning ONLY the default-domain non-fragment rows is the isolation boundary;
    // we ALSO assert the unscoped findAll() is NEVER consulted (the unfixed code path).
    @Test
    void capabilities_useDomainPinnedFragmentExcludingFinder_notFindAll() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        // The domain-pinned, fragment-excluding finder returns ONLY the default-domain
        // service rows (the real query would never hand back brandy / a fragment).
        when(repo.findByDomainAndKindNot("default", "fragment")).thenReturn(Flux.just(
                module("forum", "remote-shell", "default"),
                module("games", "remote-shell", "default")));

        List<CapabilityDto> caps = new CapabilityService(repo)
                .capabilities(PrincipalDomain.forDomain("default")).collectList().block();

        assertThat(caps).extracting(CapabilityDto::slug)
                .containsExactly("forum", "games");
        // CROSS-USER DENY (by construction of the query): no brandy slug, no profile slug.
        assertThat(caps).extracting(CapabilityDto::slug)
                .noneMatch(s -> s.startsWith("profile-"))
                .doesNotContain("brandy-secret");

        // MUTATION-RESISTANT: the unscoped findAll() (the unfixed leak) is never used.
        verify(repo).findByDomainAndKindNot("default", "fragment");
        verify(repo, never()).findAll();
    }

    // CROSS-USER DENY: a brand-X scope drives the brand-X-pinned finder, NOT a
    // brand-Y one and NOT findAll. Proven by stubbing brandx to a brand-X row and
    // leaving brandy/findAll unstubbed (would NPE / return null if wrongly called).
    @Test
    void capabilities_brandXScope_pinsToBrandX() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findByDomainAndKindNot("brandx", "fragment"))
                .thenReturn(Flux.just(module("x-svc", "remote-shell", "brandx")));

        List<CapabilityDto> caps = new CapabilityService(repo)
                .capabilities(PrincipalDomain.forDomain("brandx")).collectList().block();

        assertThat(caps).extracting(CapabilityDto::slug).containsExactly("x-svc");
        verify(repo).findByDomainAndKindNot("brandx", "fragment");
        verify(repo, never()).findByDomainAndKindNot(ArgumentMatchers.eq("brandy"), ArgumentMatchers.any());
        verify(repo, never()).findAll();
        verify(repo, never()).findByKindNot(ArgumentMatchers.any());
    }

    // SUPERADMIN: the un-pinned (all-brands) finder runs, STILL fragment-excluded
    // (findByKindNot('fragment')); the per-domain finder is NOT used.
    @Test
    void capabilities_superadmin_usesUnpinnedFragmentExcludingFinder() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findByKindNot("fragment")).thenReturn(Flux.just(
                module("x-svc", "remote-shell", "brandx"),
                module("y-svc", "remote-shell", "brandy")));

        List<CapabilityDto> caps = new CapabilityService(repo)
                .capabilities(PrincipalDomain.superadminFor(null)).collectList().block();

        assertThat(caps).extracting(CapabilityDto::slug).containsExactly("x-svc", "y-svc");
        verify(repo).findByKindNot("fragment");
        verify(repo, never()).findByDomainAndKindNot(ArgumentMatchers.any(), ArgumentMatchers.any());
        verify(repo, never()).findAll();
    }
}
