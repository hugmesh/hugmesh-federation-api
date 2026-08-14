package net.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.federation.model.SystemFinding;
import net.hugmesh.federation.repository.SystemFindingRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for {@link SystemFindingService}: file stamps reporter=@system +
 * status=held + the caller's domain (subject is the passed JWT subject); invalid
 * disposition/surface → 400; resolve loads domain-pinned (cross-domain id → 404) and
 * sets actioned/dismissed + reviewer; list routes per-domain vs superadmin.
 */
class SystemFindingServiceTest {

    /** The per-domain caller scope these tests act under (default brand). */
    private static final PrincipalDomain DEFAULT = PrincipalDomain.forDomain("default");

    private static SystemFinding held(Long id) {
        SystemFinding f = new SystemFinding();
        f.setId(id);
        f.setSubject("alice");
        f.setSurface("profile-avatar");
        f.setDisposition("flagged");
        f.setStatus("held");
        f.setDomain("default");
        return f;
    }

    @Test
    void file_stampsSystemReporter_heldStatus_subject_andDomain() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        ArgumentCaptor<SystemFinding> saved = ArgumentCaptor.forClass(SystemFinding.class);
        when(repo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.file("alice", "profile-avatar", "flagged",
                        "nsfw", 0.91, true, "ph", null, DEFAULT))
                .expectNextCount(1)
                .verifyComplete();

        SystemFinding f = saved.getValue();
        assertThat(f.getReporter()).isEqualTo("@system");
        assertThat(f.getStatus()).isEqualTo("held");
        assertThat(f.getSubject()).isEqualTo("alice");
        assertThat(f.getSurface()).isEqualTo("profile-avatar");
        assertThat(f.getDisposition()).isEqualTo("flagged");
        assertThat(f.getClassification()).isEqualTo("nsfw");
        assertThat(f.getConfidence()).isEqualTo(0.91);
        assertThat(f.getPolicyHit()).isTrue();
        assertThat(f.getDomain()).isEqualTo("default");
        assertThat(f.getTs()).isNotNull();
        // The avatar/profile path passes no subjectRef → stays null (UNAFFECTED by 037).
        assertThat(f.getSubjectRef()).isNull();
    }

    @Test
    void file_withSubjectRef_persistsTheBackReference() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        ArgumentCaptor<SystemFinding> saved = ArgumentCaptor.forClass(SystemFinding.class);
        when(repo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        SystemFindingService svc = new SystemFindingService(repo);
        // A producer filing about ONE specific moderatable row (a character-part id)
        // stamps that id as subjectRef so a later reconcile loop can address the row.
        StepVerifier.create(svc.file("alice", "character-part", "flagged",
                        "nsfw", 0.91, true, "ph", "part-42", DEFAULT))
                .expectNextCount(1)
                .verifyComplete();

        SystemFinding f = saved.getValue();
        assertThat(f.getSubjectRef()).isEqualTo("part-42");
        assertThat(f.getSurface()).isEqualTo("character-part");
        assertThat(f.getStatus()).isEqualTo("held");
    }

    @Test
    void file_invalidDisposition_is400_andNeverSaves() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.file("alice", "profile-avatar", "approve",
                        null, null, null, null, null, DEFAULT))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(400))
                .verify();
        verify(repo, never()).save(any());
    }

    @Test
    void file_blankSurface_is400() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.file("alice", "  ", "flagged", null, null, null, null, null, DEFAULT))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(400))
                .verify();
    }

    @Test
    void resolve_actioned_setsStatusAndReviewer_domainPinned() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findByIdAndDomain(7L, "default")).thenReturn(Mono.just(held(7L)));
        ArgumentCaptor<SystemFinding> saved = ArgumentCaptor.forClass(SystemFinding.class);
        when(repo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.resolve(7L, true, "mod-bob", DEFAULT))
                .expectNextCount(1)
                .verifyComplete();

        assertThat(saved.getValue().getStatus()).isEqualTo("actioned");
        assertThat(saved.getValue().getReviewer()).isEqualTo("mod-bob");
    }

    @Test
    void resolve_dismissed_setsDismissed() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findByIdAndDomain(7L, "default")).thenReturn(Mono.just(held(7L)));
        ArgumentCaptor<SystemFinding> saved = ArgumentCaptor.forClass(SystemFinding.class);
        when(repo.save(saved.capture())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.resolve(7L, false, "mod-bob", DEFAULT))
                .expectNextCount(1)
                .verifyComplete();
        assertThat(saved.getValue().getStatus()).isEqualTo("dismissed");
    }

    @Test
    void resolve_crossDomainId_is404() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findByIdAndDomain(99L, "default")).thenReturn(Mono.empty());   // belongs to another brand
        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.resolve(99L, true, "mod-bob", DEFAULT))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        verify(repo, never()).save(any());
    }

    @Test
    void list_perDomain_usesDomainScopedFinder() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findByDomainOrderByTsDesc("default")).thenReturn(Flux.just(held(1L)));
        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.list(DEFAULT)).expectNextCount(1).verifyComplete();
        verify(repo).findByDomainOrderByTsDesc("default");
        verify(repo, never()).findAllByOrderByTsDesc();
    }

    @Test
    void listByStatus_perDomain_usesStatusAndDomainFinder() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findByStatusAndDomainOrderByTsDesc("held", "default")).thenReturn(Flux.just(held(1L)));
        SystemFindingService svc = new SystemFindingService(repo);
        StepVerifier.create(svc.listByStatus("held", DEFAULT)).expectNextCount(1).verifyComplete();
        verify(repo).findByStatusAndDomainOrderByTsDesc(eq("held"), eq("default"));
    }

    // ── resolvedForReconcile: cross-domain vs domain-pinned routing + limit clamp ──

    private static SystemFinding resolved(Long id, String surface, String subjectRef) {
        SystemFinding f = held(id);
        f.setSurface(surface);
        f.setStatus("actioned");
        f.setSubjectRef(subjectRef);
        f.setReviewer("mod-bob");
        return f;
    }

    @Test
    void resolvedForReconcile_crossDomain_usesUnpinnedFinder_andProjects() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findResolvedForReconcile("character-part", 5L, 200))
                .thenReturn(Flux.just(resolved(6L, "character-part", "part-42")));
        SystemFindingService svc = new SystemFindingService(repo);

        // crossDomain=true (platform reconciler / SUPERADMIN) → un-pinned finder; the view
        // carries exactly the reconciler-facing fields.
        StepVerifier.create(svc.resolvedForReconcile("character-part", 5L, 200, true, DEFAULT))
                .assertNext(v -> {
                    assertThat(v.id()).isEqualTo(6L);
                    assertThat(v.surface()).isEqualTo("character-part");
                    assertThat(v.subjectRef()).isEqualTo("part-42");
                    assertThat(v.status()).isEqualTo("actioned");
                    assertThat(v.reviewer()).isEqualTo("mod-bob");
                    assertThat(v.domain()).isEqualTo("default");
                })
                .verifyComplete();
        verify(repo).findResolvedForReconcile("character-part", 5L, 200);
        verify(repo, never()).findResolvedForReconcileInDomain(any(), anyLong(), any(), anyInt());
    }

    @Test
    void resolvedForReconcile_perDomain_usesDomainPinnedFinder() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findResolvedForReconcileInDomain("character-sticker", 0L, "default", 200))
                .thenReturn(Flux.just(resolved(1L, "character-sticker", "sticker-7")));
        SystemFindingService svc = new SystemFindingService(repo);

        // crossDomain=false (a per-domain ADMIN) → pins to scope.domain().
        StepVerifier.create(svc.resolvedForReconcile("character-sticker", 0L, 200, false, DEFAULT))
                .expectNextCount(1)
                .verifyComplete();
        verify(repo).findResolvedForReconcileInDomain("character-sticker", 0L, "default", 200);
        verify(repo, never()).findResolvedForReconcile(any(), anyLong(), anyInt());
    }

    @Test
    void resolvedForReconcile_limitDefaultsWhenNonPositive_andIsCappedAtMax() {
        SystemFindingRepository repo = mock(SystemFindingRepository.class);
        when(repo.findResolvedForReconcile(any(), anyLong(), anyInt())).thenReturn(Flux.empty());
        SystemFindingService svc = new SystemFindingService(repo);

        // limit=0 → DEFAULT (200); a huge limit → clamped to MAX (500); negative sinceId → 0.
        svc.resolvedForReconcile("character-part", -3L, 0, true, DEFAULT).blockLast();
        svc.resolvedForReconcile("character-part", 9L, 99999, true, DEFAULT).blockLast();

        verify(repo).findResolvedForReconcile("character-part", 0L, SystemFindingService.DEFAULT_RECONCILE_LIMIT);
        verify(repo).findResolvedForReconcile("character-part", 9L, SystemFindingService.MAX_RECONCILE_LIMIT);
    }
}
