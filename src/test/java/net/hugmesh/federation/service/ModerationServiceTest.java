package net.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.federation.cache.ManifestCache;
import net.hugmesh.federation.model.FederationOverride;
import net.hugmesh.federation.model.ModerationRequest;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.federation.repository.FederationOverrideRepository;
import net.hugmesh.federation.repository.ModerationRequestRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the decide→apply chain (the previously-deferred wiring of
 * {@code ModerationService.decide(approve)} → the kill-switch surface):
 *
 * <ul>
 *   <li>an approved {@code user-removal} writes an ACTIVE scope=user
 *       {@code federation_override} row (action {@code unpublish}) tagged
 *       {@code reason='moderation_request:<id>'}, stamped with the DECIDED ROW's
 *       own domain, and invalidates the manifest cache;</li>
 *   <li>a denied {@code user-removal} clears ONLY the row(s) carrying this
 *       request's own source tag (rearm after a flipped approve; zero on a
 *       first-time deny) and never a manual kill;</li>
 *   <li>an approved {@code instance-block} stays decision-only — the catalogue has
 *       no remote-instance surface, and nothing is faked;</li>
 *   <li>an override-store failure propagates as the decide's error — the call
 *       NEVER reports success on a half-applied chain.</li>
 * </ul>
 *
 * <p>Uses the REAL {@link OverrideService} over mocked repositories so the
 * asserted override row is the one the production write path actually builds.
 */
class ModerationServiceTest {

    private static final PrincipalDomain BRANDX = PrincipalDomain.forDomain("brandx");
    private static final PrincipalDomain SUPER = PrincipalDomain.superadminFor(null);

    private final ModerationRequestRepository requests = mock(ModerationRequestRepository.class);
    private final FederationOverrideRepository overrideRepo = mock(FederationOverrideRepository.class);
    private final FederationModuleRepository moduleRepo = mock(FederationModuleRepository.class);
    private final ManifestCache cache = mock(ManifestCache.class);

    private ModerationService service() {
        when(cache.invalidate(any())).thenReturn(Mono.empty());
        return new ModerationService(requests, new OverrideService(overrideRepo, moduleRepo, cache));
    }

    private static ModerationRequest request(long id, String kind, String target, String domain) {
        ModerationRequest r = new ModerationRequest();
        r.setId(id);
        r.setKind(kind);
        r.setTarget(target);
        r.setStatus("referred");
        r.setDomain(domain);
        return r;
    }

    // ── approve user-removal → ACTIVE scope=user override, tagged + domain-stamped ──

    @Test
    void decideApprove_userRemoval_appliesTaggedUserScopeOverride() {
        ModerationRequest r = request(7L, "user-removal", "spammer", "brandx");
        when(requests.findByIdAndDomain(7L, "brandx")).thenReturn(Mono.just(r));
        when(requests.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrideRepo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(service().decide(7L, true, "admin-x", BRANDX))
                .assertNext(decided -> {
                    assertThat(decided.getStatus()).isEqualTo("approved");
                    assertThat(decided.getAdminDecider()).isEqualTo("admin-x");
                })
                .verifyComplete();

        FederationOverride row = saved.getValue();
        assertThat(row.getScope()).isEqualTo("user");
        assertThat(row.getTarget()).isEqualTo("spammer");            // keyed on owner_user_id
        assertThat(row.getAction()).isEqualTo("unpublish");
        assertThat(row.getSetBy()).isEqualTo("admin-x");
        assertThat(row.getReason()).isEqualTo("moderation_request:7"); // per-request source tag
        assertThat(row.getDomain()).isEqualTo("brandx");              // the decided row's brand
        assertThat(row.getClearedAt()).isNull();                      // ACTIVE
        // The just-removed user's modules must never be served stale -- scoped to
        // the decided row's OWN domain (per-brand cache key), never another brand's.
        verify(cache).invalidate("brandx");
        // Direct scope write — no module lookup / mutation (works when the target
        // never published a module).
        verifyNoInteractions(moduleRepo);
    }

    // ── SUPERADMIN decision lands in the decided row's brand, not "default" ──

    @Test
    void decideApprove_superadmin_overrideLandsInRequestRowDomain() {
        ModerationRequest r = request(9L, "user-removal", "spammer", "brandy");
        when(requests.findById(9L)).thenReturn(Mono.just(r));
        when(requests.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        ArgumentCaptor<FederationOverride> saved = ArgumentCaptor.forClass(FederationOverride.class);
        when(overrideRepo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(service().decide(9L, true, "super-1", SUPER))
                .expectNextCount(1)
                .verifyComplete();

        assertThat(saved.getValue().getDomain()).isEqualTo("brandy");
    }

    // ── deny user-removal → rearms ONLY this request's own tagged row(s) ──

    @Test
    void decideDeny_userRemoval_clearsOnlyThisRequestsTaggedRows() {
        ModerationRequest r = request(7L, "user-removal", "spammer", "brandx");
        when(requests.findByIdAndDomain(7L, "brandx")).thenReturn(Mono.just(r));
        when(requests.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        FederationOverride prior = new FederationOverride();
        prior.setScope("user");
        prior.setTarget("spammer");
        prior.setReason("moderation_request:7");
        prior.setDomain("brandx");
        when(overrideRepo.findByReasonAndClearedAtIsNullAndDomain("moderation_request:7", "brandx"))
                .thenReturn(Flux.just(prior));
        when(overrideRepo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(service().decide(7L, false, "admin-x", BRANDX))
                .assertNext(decided -> assertThat(decided.getStatus()).isEqualTo("denied"))
                .verifyComplete();

        // The prior approve's row is rearmed (cleared_at stamped)…
        assertThat(prior.getClearedAt()).isNotNull();
        verify(overrideRepo).save(prior);
        // …via the SOURCE-scoped domain-pinned finder — a manual kill (different /
        // NULL reason) is never touched because it never matches this source tag.
        verify(overrideRepo).findByReasonAndClearedAtIsNullAndDomain("moderation_request:7", "brandx");
    }

    @Test
    void decideDeny_userRemoval_firstTimeDeny_clearsNothingAndSucceeds() {
        ModerationRequest r = request(8L, "user-removal", "spammer", "brandx");
        when(requests.findByIdAndDomain(8L, "brandx")).thenReturn(Mono.just(r));
        when(requests.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(overrideRepo.findByReasonAndClearedAtIsNullAndDomain("moderation_request:8", "brandx"))
                .thenReturn(Flux.empty());

        StepVerifier.create(service().decide(8L, false, "admin-x", BRANDX))
                .assertNext(decided -> assertThat(decided.getStatus()).isEqualTo("denied"))
                .verifyComplete();

        verify(overrideRepo, never()).save(any());
    }

    // ── approve instance-block → decision-only (honest: no instance surface) ──

    @Test
    void decideApprove_instanceBlock_isDecisionOnly_noOverrideWrite() {
        ModerationRequest r = request(5L, "instance-block", "evil.example", "brandx");
        when(requests.findByIdAndDomain(5L, "brandx")).thenReturn(Mono.just(r));
        when(requests.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(service().decide(5L, true, "admin-x", BRANDX))
                .assertNext(decided -> assertThat(decided.getStatus()).isEqualTo("approved"))
                .verifyComplete();

        verifyNoInteractions(overrideRepo);
        verifyNoInteractions(moduleRepo);
    }

    // ── override-store failure → the decide errors (never fake success) ──

    @Test
    void decideApprove_overrideWriteFails_decideErrors() {
        ModerationRequest r = request(7L, "user-removal", "spammer", "brandx");
        when(requests.findByIdAndDomain(7L, "brandx")).thenReturn(Mono.just(r));
        when(requests.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(overrideRepo.save(any())).thenReturn(Mono.error(new IllegalStateException("store down")));

        StepVerifier.create(service().decide(7L, true, "admin-x", BRANDX))
                .expectErrorMessage("store down")
                .verify();
    }
}
