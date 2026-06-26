package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.model.SystemFinding;
import systems.snapdragon.federation.repository.SystemFindingRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
}
