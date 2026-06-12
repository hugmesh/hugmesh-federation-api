package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;
import systems.snapdragon.federation.security.DomainScope;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The MANIFEST per-domain CUT + SUPERADMIN tier, delineated per the test standard.
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a per-domain caller's manifest is rendered from
 *       the DOMAIN-pinned finders (their own brand's remotes only).</li>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — the SUPERADMIN tier renders from the
 *       un-pinned finders (every brand's remotes in one manifest).</li>
 *   <li><b>CROSS-USER</b> — the per-domain finder is the ISOLATION boundary: a
 *       brand-X caller never consults the un-pinned finder, so a brand-Y remote can
 *       never appear in brand-X's manifest; and a brand-X scope=all kill is applied
 *       only to brand-X's render.</li>
 * </ul>
 */
class ManifestDomainCutTest {

    private static FederationModule module(String slug, String visibility) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility(visibility);
        m.setEnabled(true);
        m.setCircuitState("closed");
        return m;
    }

    private static ManifestCache noopCache() {
        ManifestCache cache = mock(ManifestCache.class);
        when(cache.put(any())).thenReturn(Mono.empty());
        return cache;
    }

    // USER-SITUATIONAL: a brand-X caller's manifest comes from the brandx-pinned
    // finders; the un-pinned (all-brands) finder is NEVER consulted.
    @Test
    void perDomainCaller_rendersFromDomainPinnedFinders() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "brandx"))
                .thenReturn(Flux.just(module("x-login", "public")));
        when(ovr.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq("brandx")))
                .thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        FederationManifestDto manifest =
                svc.render(Set.of("ROLE_USER"), DomainScope.of("brandx")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("x-login");
        // CROSS-USER isolation: the all-brands finder is never touched.
        verify(repo, never()).findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(any());
        verify(ovr, never()).findByScopeInAndClearedAtIsNull(anyCollection());
    }

    // MULTIUSER-SITUATIONAL: the SUPERADMIN tier renders from the un-pinned finders
    // (cross-domain control plane sees every brand).
    @Test
    void superadminTier_rendersFromUnpinnedFinders_sees_all_brands() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed"))
                .thenReturn(Flux.just(module("x-login", "public"), module("y-login", "public")));
        when(ovr.findByScopeInAndClearedAtIsNull(anyCollection())).thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        FederationManifestDto manifest =
                svc.render(Set.of("ROLE_SUPERADMIN"), DomainScope.superadmin()).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("x-login", "y-login");
        // The domain-pinned finder is NOT used by the superadmin tier.
        verify(repo, never())
                .findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(any(), any());
    }

    // SUPERADMIN sees internal-visibility remotes too (it is the infra role).
    @Test
    void superadminTier_seesInternalRemotes() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed"))
                .thenReturn(Flux.just(module("admin", "internal")));
        when(ovr.findByScopeInAndClearedAtIsNull(anyCollection())).thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        FederationManifestDto manifest =
                svc.render(Set.of("ROLE_SUPERADMIN"), DomainScope.superadmin()).block();
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("admin");
    }

    // CROSS-USER: the cache write-through is suppressed for a NON-default domain so a
    // brand-X render never poisons the canonical default public cache.
    @Test
    void nonDefaultDomain_doesNotWriteThroughCache() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "brandx"))
                .thenReturn(Flux.just(module("x-login", "public")));
        when(ovr.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq("brandx")))
                .thenReturn(Flux.empty());
        ManifestCache cache = noopCache();

        ManifestService svc = new ManifestService(repo, ovr, cache);
        svc.render(Set.of("ROLE_USER"), DomainScope.of("brandx")).block();
        verify(cache, never()).put(any());
    }

    // The DEFAULT-domain public render still writes through (back-compat cache rule).
    @Test
    void defaultDomain_publicRender_writesThroughCache() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "default"))
                .thenReturn(Flux.just(module("login", "public")));
        when(ovr.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq("default")))
                .thenReturn(Flux.empty());
        ManifestCache cache = noopCache();

        ManifestService svc = new ManifestService(repo, ovr, cache);
        svc.render(Set.of("ROLE_USER"), DomainScope.of("default")).block();
        verify(cache).put(any());
    }

    // CROSS-USER: the internal-visibility cut is ORTHOGONAL to the domain cut — a
    // per-domain NON-ADMIN sees ONLY their brand's PUBLIC rows; the internal row is
    // dropped even though it is in their own brand.
    @Test
    void perDomainNonAdmin_seesOnlyOwnBrandPublicRows_internalDropped() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "brandx"))
                .thenReturn(Flux.just(module("x-login", "public"), module("x-admin", "internal")));
        when(ovr.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq("brandx")))
                .thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        FederationManifestDto manifest =
                svc.render(Set.of("ROLE_USER"), DomainScope.of("brandx")).block();

        // own brand's PUBLIC row only — the internal row needs ADMIN/INTERNAL.
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("x-login");
    }

    // A per-domain ADMIN sees their brand's internal rows too (the internal cut keys
    // off ROLE_ADMIN/INTERNAL, not the domain).
    @Test
    void perDomainAdmin_seesOwnBrandInternalRows() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "brandx"))
                .thenReturn(Flux.just(module("x-login", "public"), module("x-admin", "internal")));
        when(ovr.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq("brandx")))
                .thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        FederationManifestDto manifest =
                svc.render(Set.of("ROLE_USER", "ROLE_ADMIN"), DomainScope.of("brandx")).block();
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("x-login", "x-admin");
    }

    // CROSS-USER FAIL-CLOSED: a principal whose issuer could not be resolved is pinned
    // to the NO_DOMAIN sentinel; the domain-pinned finder is asked for that sentinel
    // (which matches NO row), so the manifest is EMPTY — never silently cross-domain
    // nor un-pinned (the all-brands finder is never touched).
    @Test
    void unresolvedIssuerScope_rendersEmpty_neverLeaksAnotherBrand() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        // The sentinel pins both finders; with no rows tagged " no-domain" they return
        // empty (here stubbed empty to model the real no-match query).
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(
                eq("closed"), eq(DomainScope.NO_DOMAIN)))
                .thenReturn(Flux.empty());
        when(ovr.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq(DomainScope.NO_DOMAIN)))
                .thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        DomainScope failClosed = DomainScope.of(null); // collapses to NO_DOMAIN
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER"), failClosed).block();

        assertThat(manifest.remotes()).isEmpty();
        // The query was pinned to the sentinel, NOT run un-pinned (all-brands).
        verify(repo).findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(
                "closed", DomainScope.NO_DOMAIN);
        verify(repo, never()).findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(any());
    }

    // A SUPERADMIN authority set with NO explicit domain (back-compat render(Set))
    // still gets the cross-domain tier.
    @Test
    void backCompatRender_superadminAuthorities_getCrossDomainTier() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationOverrideRepository ovr = mock(FederationOverrideRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed"))
                .thenReturn(Flux.just(module("x-login", "public"), module("y-login", "public")));
        when(ovr.findByScopeInAndClearedAtIsNull(anyCollection())).thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        StepVerifier.create(svc.render(Set.of("ROLE_SUPERADMIN")))
                .assertNext(m -> assertThat(m.remotes()).hasSize(2))
                .verifyComplete();
        verify(repo).findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed");
    }
}
