package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the kill-switch service: apply records an ACTIVE scope
 * override row (cleared_at NULL) AND still mutates the targeted module per the
 * action; clearScope stamps cleared_at (rearm); per-module slug rearm unchanged.
 *
 * <p>Also covers the account-states profile-ban path: applyUserScope writes a
 * scope=user row DIRECTLY (no module lookup -> fixes the 404), tagged with the
 * SOURCE so clearScopeBySource clears ONLY rows it owns (never an unrelated manual
 * kill), and both invalidate the manifest cache.
 */
class OverrideServiceTest {

    private static FederationModule module(String slug) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setEnabled(true);
        m.setCircuitState("closed");
        return m;
    }

    /** A ManifestCache stub whose invalidate()/put() are best-effort no-ops. */
    private static ManifestCache noopCache() {
        ManifestCache cache = mock(ManifestCache.class);
        when(cache.invalidate()).thenReturn(Mono.empty());
        when(cache.put(any())).thenReturn(Mono.empty());
        return cache;
    }

    private static OverrideService service(FederationOverrideRepository overrides,
                                           FederationModuleRepository modules) {
        return new OverrideService(overrides, modules, noopCache());
    }

    @Test
    void apply_circuitBreak_mutatesModule_andRecordsActiveScopeRow() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        FederationModule m = module("admin");
        when(modules.findBySlug("admin")).thenReturn(Mono.just(m));
        when(modules.save(any())).thenReturn(Mono.just(m));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = service(overrides, modules);

        StepVerifier.create(svc.apply("admin", "role", "admin", "circuit-break", "set-by-1"))
                .expectNextCount(1)
                .verifyComplete();

        // Per-module mutation unchanged: circuit_state flipped to open + saved.
        assertThat(m.getCircuitState()).isEqualTo("open");
        verify(modules).save(m);

        // Active scope row recorded: cleared_at NULL, target = scope_value (role).
        FederationOverride row = saved.getValue();
        assertThat(row.getScope()).isEqualTo("role");
        assertThat(row.getTarget()).isEqualTo("admin");
        assertThat(row.getAction()).isEqualTo("circuit-break");
        assertThat(row.getClearedAt()).isNull();
    }

    @Test
    void apply_scopeAll_recordsNullTarget() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        FederationModule m = module("host");
        when(modules.findBySlug("host")).thenReturn(Mono.just(m));
        when(modules.save(any())).thenReturn(Mono.just(m));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = service(overrides, modules);

        svc.apply("host", "all", null, "unpublish", "set-by-1").block();

        FederationOverride row = saved.getValue();
        assertThat(row.getScope()).isEqualTo("all");
        assertThat(row.getTarget()).isNull(); // scope=all => NULL target (global key)
        assertThat(row.getClearedAt()).isNull();
        assertThat(m.isEnabled()).isFalse(); // unpublish still flips enabled=false
    }

    @Test
    void apply_user_withoutScopeValue_fallsBackToSlugTarget() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        FederationModule m = module("some-slug");
        when(modules.findBySlug("some-slug")).thenReturn(Mono.just(m));
        when(modules.save(any())).thenReturn(Mono.just(m));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = service(overrides, modules);
        svc.apply("some-slug", "user", "", "circuit-break", "set-by-1").block();

        // No scope_value given => target falls back to the slug (per-slug intent).
        assertThat(saved.getValue().getTarget()).isEqualTo("some-slug");
    }

    @Test
    void apply_rejectsBadAction() {
        OverrideService svc = service(
                mock(FederationOverrideRepository.class), mock(FederationModuleRepository.class));
        StepVerifier.create(svc.apply("x", "all", null, "nuke", "set-by-1"))
                .expectError()
                .verify();
    }

    @Test
    void clearScope_user_stampsClearedAtOnActiveRows() {
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        FederationOverride active = new FederationOverride();
        active.setScope("user");
        active.setTarget("ownerX");
        when(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "ownerX"))
                .thenReturn(Flux.just(active));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = service(overrides, mock(FederationModuleRepository.class));

        StepVerifier.create(svc.clearScope("user", "ownerX"))
                .expectNext(1L)
                .verifyComplete();

        assertThat(saved.getValue().getClearedAt()).isNotNull();
    }

    @Test
    void clearScope_all_keysOnScopeAlone() {
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        FederationOverride active = new FederationOverride();
        active.setScope("all");
        when(overrides.findByScopeAndClearedAtIsNull("all")).thenReturn(Flux.just(active));
        when(overrides.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = service(overrides, mock(FederationModuleRepository.class));

        StepVerifier.create(svc.clearScope("all", null))
                .expectNext(1L)
                .verifyComplete();

        // The all-variant finder (not the target one) is consulted.
        verify(overrides).findByScopeAndClearedAtIsNull("all");
        verify(overrides, never()).findByScopeAndTargetAndClearedAtIsNull(eq("all"), any());
    }

    @Test
    void clearScope_rejectsBadScope() {
        OverrideService svc = service(
                mock(FederationOverrideRepository.class), mock(FederationModuleRepository.class));
        StepVerifier.create(svc.clearScope("bogus", "x"))
                .expectError()
                .verify();
    }

    @Test
    void slugRearm_unchanged_flipsCircuitClosedAndEnabled() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        FederationModule m = module("admin");
        m.setCircuitState("open");
        m.setEnabled(false);
        when(modules.findBySlug("admin")).thenReturn(Mono.just(m));
        when(modules.save(any())).thenReturn(Mono.just(m));

        OverrideService svc = service(mock(FederationOverrideRepository.class), modules);

        svc.rearm("admin").block();
        assertThat(m.getCircuitState()).isEqualTo("closed");
        assertThat(m.isEnabled()).isTrue();
    }

    // ── Account-states profile-ban path ─────────────────────────────────────────

    @Test
    void applyUserScope_writesActiveUserRowDirectly_noModuleLookup_taggedBySource() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        ManifestCache cache = noopCache();
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = new OverrideService(overrides, modules, cache);

        StepVerifier.create(svc.applyUserScope("alice", "unpublish", "mod-1", "access_suspension:42"))
                .expectNextCount(1)
                .verifyComplete();

        // NO module lookup at all — this is the fix for the prior 404 when a banned
        // user has never published a module.
        verify(modules, never()).findBySlug(any());
        verify(modules, never()).save(any());

        FederationOverride row = saved.getValue();
        assertThat(row.getScope()).isEqualTo("user");
        assertThat(row.getTarget()).isEqualTo("alice");          // keyed on owner_user_id
        assertThat(row.getAction()).isEqualTo("unpublish");
        assertThat(row.getSetBy()).isEqualTo("mod-1");
        assertThat(row.getReason()).isEqualTo("access_suspension:42"); // SOURCE tag
        assertThat(row.getClearedAt()).isNull();                 // ACTIVE
        assertThat(row.getTs()).isNotNull();

        // The just-banned profile must never be served stale -> cache invalidated.
        verify(cache).invalidate();
    }

    @Test
    void applyUserScope_requiresOwner_action_andSource() {
        OverrideService svc = service(
                mock(FederationOverrideRepository.class), mock(FederationModuleRepository.class));

        StepVerifier.create(svc.applyUserScope("  ", "unpublish", "mod-1", "access_suspension:1"))
                .expectError().verify();
        StepVerifier.create(svc.applyUserScope("alice", "nuke", "mod-1", "access_suspension:1"))
                .expectError().verify();
        StepVerifier.create(svc.applyUserScope("alice", "unpublish", "mod-1", "  "))
                .expectError().verify();
    }

    @Test
    void clearScopeBySource_clearsOnlyOwnRows_andInvalidatesCache() {
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        ManifestCache cache = noopCache();

        FederationOverride mine = new FederationOverride();
        mine.setScope("user");
        mine.setTarget("alice");
        mine.setReason("access_suspension:42");
        when(overrides.findByReasonAndClearedAtIsNull("access_suspension:42"))
                .thenReturn(Flux.just(mine));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrides.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        OverrideService svc = new OverrideService(overrides, mock(FederationModuleRepository.class), cache);

        StepVerifier.create(svc.clearScopeBySource("access_suspension:42"))
                .expectNext(1L)
                .verifyComplete();

        // Only the source-scoped finder is consulted (NOT the broad scope/target
        // clear) so an unrelated manual kill is never rearmed.
        verify(overrides).findByReasonAndClearedAtIsNull("access_suspension:42");
        verify(overrides, never()).findByScopeAndTargetAndClearedAtIsNull(any(), any());
        assertThat(saved.getValue().getClearedAt()).isNotNull(); // rearmed
        verify(cache).invalidate();
    }

    @Test
    void clearScopeBySource_doesNotRearmUnrelatedManualKill() {
        // The suspension's source finds NO matching row (a manual scope=user kill an
        // admin applied has a NULL reason, so the source-scoped finder skips it).
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        when(overrides.findByReasonAndClearedAtIsNull("access_suspension:99"))
                .thenReturn(Flux.empty());

        OverrideService svc = service(overrides, mock(FederationModuleRepository.class));

        StepVerifier.create(svc.clearScopeBySource("access_suspension:99"))
                .expectNext(0L) // nothing of ours to clear
                .verifyComplete();

        // The manual kill's row is never saved/stamped -> it stays ACTIVE.
        verify(overrides, never()).save(any());
    }

    @Test
    void clearScopeBySource_requiresSource() {
        OverrideService svc = service(
                mock(FederationOverrideRepository.class), mock(FederationModuleRepository.class));
        StepVerifier.create(svc.clearScopeBySource("  ")).expectError().verify();
    }
}
