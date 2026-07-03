package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;
import systems.snapdragon.federation.repository.ModerationRequestRepository;
import systems.snapdragon.commons.security.PrincipalDomain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The DOMAIN-SCOPING security keystone for the federation-api service layer,
 * delineated per the platform test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a single per-domain principal acting on its OWN
 *       brand's rows (the ALLOW path: the domain-pinned finder is consulted).</li>
 *   <li><b>MULTIUSER-SITUATIONAL</b> — an admin over a domain vs the SUPERADMIN
 *       cross-domain control plane (each runs a different finder).</li>
 *   <li><b>CROSS-USER</b> — the ISOLATION BOUNDARY: a brand-X principal is DENIED
 *       brand-Y data (a cross-domain slug/id resolves to 404 because the
 *       domain-pinned finder returns empty), and a write is STAMPED with the
 *       caller's domain (never a body value), so it can never land cross-domain.</li>
 * </ul>
 *
 * <p>Services are exercised against mocked repositories so the assertion is the
 * EXACT finder + the domain stamp — proving the cut is enforced in the QUERY, not
 * (spoofably) in code. CONCURRENT coverage lives in
 * {@link systems.snapdragon.federation.repository} (real-DB) +
 * {@code ManifestDomainCutTest}.
 */
class DomainScopeServiceTest {

    private static final PrincipalDomain BRANDX = PrincipalDomain.forDomain("brandx");
    private static final PrincipalDomain BRANDY = PrincipalDomain.forDomain("brandy");
    private static final PrincipalDomain SUPER = PrincipalDomain.superadminFor(null);

    private static FederationModule module(String slug, String domain) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility("public");
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setDomain(domain);
        return m;
    }

    // ───────────────────────────── ModuleRegistryService ─────────────────────────────

    @Nested
    class ModuleRegistry {

        private final FederationModuleRepository repo = mock(FederationModuleRepository.class);
        private final UsernameAvailabilityService usernames = mock(UsernameAvailabilityService.class);
        private final ModuleRegistryService svc = new ModuleRegistryService(repo, usernames);

        // USER-SITUATIONAL: a per-domain admin lists only their own brand.
        @Test
        void list_perDomain_consultsDomainPinnedFinder() {
            when(repo.findByDomain("brandx")).thenReturn(Flux.just(module("x-mod", "brandx")));
            StepVerifier.create(svc.list(BRANDX)).expectNextCount(1).verifyComplete();
            verify(repo).findByDomain("brandx");
            verify(repo, never()).findAll();
        }

        // MULTIUSER-SITUATIONAL: SUPERADMIN lists every brand (un-pinned finder).
        @Test
        void list_superadmin_consultsUnpinnedFinder() {
            when(repo.findAll()).thenReturn(Flux.just(module("x-mod", "brandx"), module("y-mod", "brandy")));
            StepVerifier.create(svc.list(SUPER)).expectNextCount(2).verifyComplete();
            verify(repo).findAll();
            verify(repo, never()).findByDomain(any());
        }

        // CROSS-USER DENY: brand-X admin asking for a brand-Y slug gets 404 (the
        // domain-pinned finder returns empty — the cross-domain row is never surfaced).
        @Test
        void get_crossDomainSlug_is404_neverLeaksOtherBrandRow() {
            when(repo.findBySlugAndDomain("y-only", "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc.get("y-only", BRANDX)).expectError().verify();
            verify(repo).findBySlugAndDomain("y-only", "brandx");
            verify(repo, never()).findBySlug(any());
        }

        // CROSS-USER (write isolation): create STAMPS the caller's domain, ignoring
        // any body-supplied domain — a client can never plant a row in another brand.
        @Test
        void create_stampsCallerDomain_ignoringBodyDomain() {
            FederationModule body = module("new-mod", "brandy"); // attacker sets brandy
            when(repo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
            when(usernames.grant(any(), any())).thenReturn(Mono.empty());

            ArgumentCaptor<FederationModule> saved = ArgumentCaptor.forClass(FederationModule.class);
            svc.create(body, BRANDX).block();
            verify(repo).save(saved.capture());
            // The caller's domain (brandx) wins — the spoofed body 'brandy' is overwritten.
            assertThat(saved.getValue().getDomain()).isEqualTo("brandx");
        }

        // CROSS-USER DENY: update/delete a cross-domain slug -> 404 (domain-pinned load).
        @Test
        void update_crossDomainSlug_is404() {
            when(repo.findBySlugAndDomain("y-only", "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc.update("y-only", module("y-only", "brandx"), BRANDX))
                    .expectError().verify();
            verify(repo, never()).findBySlug(any());
        }

        @Test
        void delete_crossDomainSlug_is404() {
            when(repo.findBySlugAndDomain("y-only", "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc.delete("y-only", BRANDX)).expectError().verify();
            verify(repo, never()).findBySlug(any());
        }

        // CROSS-USER (update isolation): the domain column is NOT patchable — an
        // update keeps the loaded row's domain even if the patch tries to re-home it.
        @Test
        void update_doesNotRehomeRowToAnotherBrand() {
            FederationModule existing = module("x-mod", "brandx");
            when(repo.findBySlugAndDomain("x-mod", "brandx")).thenReturn(Mono.just(existing));
            when(repo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

            FederationModule patch = module("x-mod", "brandy"); // attempt to re-home
            patch.setDisplayName("renamed");
            ArgumentCaptor<FederationModule> saved = ArgumentCaptor.forClass(FederationModule.class);
            svc.update("x-mod", patch, BRANDX).block();
            verify(repo).save(saved.capture());
            assertThat(saved.getValue().getDomain()).isEqualTo("brandx"); // unchanged
            assertThat(saved.getValue().getDisplayName()).isEqualTo("renamed");
        }

        // MULTIUSER-SITUATIONAL: SUPERADMIN get/update/delete uses the un-pinned slug
        // finder (reaches any brand).
        @Test
        void superadmin_get_usesUnpinnedSlugFinder() {
            when(repo.findBySlug("y-only")).thenReturn(Mono.just(module("y-only", "brandy")));
            StepVerifier.create(svc.get("y-only", SUPER)).expectNextCount(1).verifyComplete();
            verify(repo).findBySlug("y-only");
            verify(repo, never()).findBySlugAndDomain(any(), any());
        }
    }

    // ───────────────────────────── OverrideService ─────────────────────────────

    @Nested
    class Override {

        private final FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        private final FederationModuleRepository modules = mock(FederationModuleRepository.class);
        private final ManifestCache cache = mock(ManifestCache.class);
        private OverrideService svc() {
            when(cache.invalidate(any())).thenReturn(Mono.empty());
            return new OverrideService(overrides, modules, cache);
        }

        // USER-SITUATIONAL: a per-domain admin lists only their brand's overrides.
        @Test
        void list_perDomain_consultsDomainPinnedFinder() {
            when(overrides.findByDomainOrderByTsDesc("brandx")).thenReturn(Flux.empty());
            svc().list(BRANDX).collectList().block();
            verify(overrides).findByDomainOrderByTsDesc("brandx");
            verify(overrides, never()).findAllByOrderByTsDesc();
        }

        // CROSS-USER DENY: applying an override against a brand-Y module as brand-X
        // is a 404 (the targeted module is loaded domain-pinned).
        @Test
        void apply_crossDomainModule_is404() {
            when(modules.findBySlugAndDomain("y-mod", "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc().apply("y-mod", "all", null, "circuit-break", "admin-x", BRANDX))
                    .expectError().verify();
            verify(modules, never()).findBySlug(any());
        }

        // CROSS-USER (write isolation): the recorded override row is STAMPED with the
        // caller's domain so a scope=all kill never blanks another brand's manifest.
        @Test
        void apply_stampsCallerDomainOnAuditRow() {
            FederationModule m = module("x-mod", "brandx");
            when(modules.findBySlugAndDomain("x-mod", "brandx")).thenReturn(Mono.just(m));
            when(modules.save(any())).thenReturn(Mono.just(m));
            ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
            when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

            svc().apply("x-mod", "all", null, "circuit-break", "admin-x", BRANDX).block();
            assertThat(saved.getValue().getDomain()).isEqualTo("brandx");
        }

        // CROSS-USER DENY: clearScope only clears the caller's own domain rows — a
        // brand-X admin clearing a scope that matched a brand-Y active row leaves it.
        @Test
        void clearScope_doesNotClearOtherBrandRow() {
            FederationOverride mine = new FederationOverride();
            mine.setScope("user"); mine.setTarget("u1"); mine.setDomain("brandx");
            FederationOverride theirs = new FederationOverride();
            theirs.setScope("user"); theirs.setTarget("u1"); theirs.setDomain("brandy");
            when(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "u1"))
                    .thenReturn(Flux.just(mine, theirs));
            ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
            when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

            // brand-X admin clears: ONLY 'mine' (brandx) is stamped; 'theirs' (brandy) survives.
            StepVerifier.create(svc().clearScope("user", "u1", BRANDX)).expectNext(1L).verifyComplete();
            assertThat(saved.getAllValues()).hasSize(1);
            assertThat(saved.getValue().getDomain()).isEqualTo("brandx");
        }

        // MULTIUSER-SITUATIONAL: SUPERADMIN clearScope clears matching rows in EVERY brand.
        @Test
        void clearScope_superadmin_clearsAllBrands() {
            FederationOverride x = new FederationOverride();
            x.setScope("user"); x.setTarget("u1"); x.setDomain("brandx");
            FederationOverride y = new FederationOverride();
            y.setScope("user"); y.setTarget("u1"); y.setDomain("brandy");
            when(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "u1"))
                    .thenReturn(Flux.just(x, y));
            when(overrides.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

            StepVerifier.create(svc().clearScope("user", "u1", SUPER)).expectNext(2L).verifyComplete();
        }

        // CROSS-USER DENY: a per-domain rearm of a cross-domain module is a 404.
        @Test
        void rearm_crossDomainModule_is404() {
            when(modules.findBySlugAndDomain("y-mod", "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc().rearm("y-mod", BRANDX)).expectError().verify();
            verify(modules, never()).findBySlug(any());
        }

        // CROSS-USER (suspension write isolation): the direct user-scope ban stamps
        // the suspending principal's domain.
        @Test
        void applyUserScope_stampsCallerDomain() {
            ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
            when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
            svc().applyUserScope("alice", "unpublish", "mod-y", "access_suspension:7", BRANDY).block();
            assertThat(saved.getValue().getDomain()).isEqualTo("brandy");
        }

        // Back-compat overload lands in 'default' (single-issuer / legacy callers).
        @Test
        void applyUserScope_backCompatOverload_landsInDefault() {
            ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
            when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
            svc().applyUserScope("alice", "unpublish", "mod-1", "access_suspension:8").block();
            assertThat(saved.getValue().getDomain()).isEqualTo("default");
        }
    }

    // ───────────────────────────── ModerationService ─────────────────────────────

    @Nested
    class Moderation {

        private final ModerationRequestRepository repo = mock(ModerationRequestRepository.class);
        // The decide→apply chain is exercised in ModerationServiceTest; the domain-cut
        // tests here decide rows with no kind, so the mocked OverrideService is inert.
        private final ModerationService svc = new ModerationService(repo, mock(OverrideService.class));

        // USER-SITUATIONAL: a per-domain mod lists only their brand's requests.
        @Test
        void list_perDomain_consultsDomainPinnedFinder() {
            when(repo.findByDomainOrderByTsDesc("brandx")).thenReturn(Flux.empty());
            svc.list(BRANDX).collectList().block();
            verify(repo).findByDomainOrderByTsDesc("brandx");
            verify(repo, never()).findAllByOrderByTsDesc();
        }

        @Test
        void listByStatus_perDomain_consultsDomainPinnedFinder() {
            when(repo.findByStatusAndDomainOrderByTsDesc("recommended", "brandx")).thenReturn(Flux.empty());
            svc.listByStatus("recommended", BRANDX).collectList().block();
            verify(repo).findByStatusAndDomainOrderByTsDesc("recommended", "brandx");
            verify(repo, never()).findByStatusOrderByTsDesc(any());
        }

        // MULTIUSER-SITUATIONAL: SUPERADMIN lists every brand's requests.
        @Test
        void list_superadmin_consultsUnpinnedFinder() {
            when(repo.findAllByOrderByTsDesc()).thenReturn(Flux.empty());
            svc.list(SUPER).collectList().block();
            verify(repo).findAllByOrderByTsDesc();
            verify(repo, never()).findByDomainOrderByTsDesc(any());
        }

        // CROSS-USER (write isolation): submit STAMPS the requester's domain.
        @Test
        void submit_stampsRequesterDomain() {
            ArgumentCaptor<ModerationRequest> saved = ArgumentCaptor.forClass(ModerationRequest.class);
            when(repo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
            svc.submit("mod-x", "instance-block", "evil.example", "spam", BRANDX).block();
            assertThat(saved.getValue().getDomain()).isEqualTo("brandx");
        }

        // CROSS-USER DENY: refer/decide a cross-domain request id -> 404 (the row is
        // loaded domain-pinned, so a brand-X mod/admin can never touch brand-Y's).
        @Test
        void refer_crossDomainId_is404() {
            when(repo.findByIdAndDomain(99L, "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc.refer(99L, "mod-x", BRANDX)).expectError().verify();
            verify(repo, never()).findById(any(Long.class));
        }

        @Test
        void decide_crossDomainId_is404() {
            when(repo.findByIdAndDomain(99L, "brandx")).thenReturn(Mono.empty());
            StepVerifier.create(svc.decide(99L, true, "admin-x", BRANDX)).expectError().verify();
            verify(repo, never()).findById(any(Long.class));
        }

        // MULTIUSER-SITUATIONAL: SUPERADMIN decide uses the un-pinned id finder.
        @Test
        void decide_superadmin_usesUnpinnedFinder() {
            ModerationRequest r = new ModerationRequest();
            r.setDomain("brandy");
            when(repo.findById(5L)).thenReturn(Mono.just(r));
            when(repo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
            svc.decide(5L, true, "super-1", SUPER).block();
            verify(repo).findById(5L);
            verify(repo, never()).findByIdAndDomain(eq(5L), any());
        }
    }
}
