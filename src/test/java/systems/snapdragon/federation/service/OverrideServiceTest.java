package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
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
 */
class OverrideServiceTest {

    private static FederationModule module(String slug) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setEnabled(true);
        m.setCircuitState("closed");
        return m;
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

        OverrideService svc = new OverrideService(overrides, modules);

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

        OverrideService svc = new OverrideService(overrides, modules);

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

        OverrideService svc = new OverrideService(overrides, modules);
        svc.apply("some-slug", "user", "", "circuit-break", "set-by-1").block();

        // No scope_value given => target falls back to the slug (per-slug intent).
        assertThat(saved.getValue().getTarget()).isEqualTo("some-slug");
    }

    @Test
    void apply_rejectsBadAction() {
        OverrideService svc = new OverrideService(
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

        OverrideService svc = new OverrideService(overrides, mock(FederationModuleRepository.class));

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

        OverrideService svc = new OverrideService(overrides, mock(FederationModuleRepository.class));

        StepVerifier.create(svc.clearScope("all", null))
                .expectNext(1L)
                .verifyComplete();

        // The all-variant finder (not the target one) is consulted.
        verify(overrides).findByScopeAndClearedAtIsNull("all");
        verify(overrides, never()).findByScopeAndTargetAndClearedAtIsNull(eq("all"), any());
    }

    @Test
    void clearScope_rejectsBadScope() {
        OverrideService svc = new OverrideService(
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

        OverrideService svc = new OverrideService(mock(FederationOverrideRepository.class), modules);

        svc.rearm("admin").block();
        assertThat(m.getCircuitState()).isEqualTo("closed");
        assertThat(m.isEnabled()).isTrue();
    }
}
