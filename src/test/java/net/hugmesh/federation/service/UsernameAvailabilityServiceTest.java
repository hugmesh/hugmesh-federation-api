package net.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.federation.model.UsernameAvailabilityDto;
import net.hugmesh.federation.model.UsernameSkeleton;
import net.hugmesh.federation.repository.UsernameSkeletonRepository;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the availability ENGINE: the match-tier ordering (reserved
 * before user-collision), self-exclusion by EXACT username only, the override
 * rules, and the registration-grant skeleton write. The repository is mocked; the
 * real {@link UsernameSkeletonService} does the folding.
 */
class UsernameAvailabilityServiceTest {

    private final UsernameSkeletonService skel = new UsernameSkeletonService();
    private final UsernameSkeletonRepository repo = mock(UsernameSkeletonRepository.class);
    private final UsernameAvailabilityService svc = new UsernameAvailabilityService(skel, repo);

    private static UsernameSkeleton row(String username, String skeleton) {
        return new UsernameSkeleton(username, username, skeleton, skeleton.substring(0, 1), "77.1", Instant.now());
    }

    // ── available: no collision, not reserved ────────────────────────────────────

    @Test
    void available_whenNoCollisionAndNotReserved() {
        when(repo.findBySkeleton(anyString())).thenReturn(Flux.empty());

        StepVerifier.create(svc.check("charlie", null))
                .assertNext(r -> {
                    assertThat(r.available()).isTrue();
                    assertThat(r.collide()).isFalse();
                    assertThat(r.reason()).isNull();
                    assertThat(r.skeleton()).isEqualTo(skel.skeleton("charlie"));
                })
                .verifyComplete();
    }

    // ── reason=reserved (EXACT tier b only) — checked BEFORE user collision, no DB hit ──

    @Test
    void reserved_confusable_isReason_reserved_andSkipsDb() {
        StepVerifier.create(svc.check("4dmin", null))
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.reason()).isEqualTo("reserved");
                    assertThat(r.matchedWith()).isEqualTo("admin");
                })
                .verifyComplete();

        // Reserved short-circuits BEFORE the DB collision scan.
        verify(repo, never()).findBySkeleton(anyString());
    }

    @Test
    void exactReservedSkeleton_staysReserved_andIsNeverOverridable() {
        // Regression for the tier split: the EXACT reserved-skeleton tier (b) — a
        // genuine confusable like "4dmin ~ admin" — must remain reason=reserved and
        // survive an admin override=confusable (never freed).
        StepVerifier.create(svc.check("4dmin", null))
                .assertNext(r -> {
                    assertThat(r.reason()).isEqualTo("reserved");
                    assertThat(UsernameAvailabilityService
                            .applyConfusableOverride(r).available()).isFalse();
                })
                .verifyComplete();
    }

    // ── reason=confusable (FUZZY typo-squat / affix tiers c/d) — ADMIN-overridable ──
    // The service used to label these "reserved" too, so a legitimate name that merely
    // resembled a reserved label (e.g. "administrator", "admin01") was permanently
    // unregisterable with NO admin escape hatch. The fuzzy tiers are heuristic, so the
    // documented contract makes them reason=confusable (ROLE_ADMIN-overridable).

    @Test
    void fuzzyReservedTypoSquat_isReason_confusable_overridable_andSkipsDb() {
        // "administrator" is NOT an exact reserved-skeleton; it matches "admin" via the
        // length-scaled edit-distance typo-squat tier (c).
        StepVerifier.create(svc.check("administrator", null))
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.reason()).isEqualTo("confusable");
                    assertThat(r.matchedWith()).isEqualTo("admin");
                    // the admin escape hatch now works (the whole point of the fix):
                    assertThat(UsernameAvailabilityService
                            .applyConfusableOverride(r).available()).isTrue();
                })
                .verifyComplete();
        // Reserved tiers still short-circuit BEFORE the DB collision scan.
        verify(repo, never()).findBySkeleton(anyString());
    }

    @Test
    void fuzzyReservedAffix_isReason_confusable_andOverridable() {
        // "admin01" matches "admin" via the affix anti-impersonation tier (d).
        StepVerifier.create(svc.check("admin01", null))
                .assertNext(r -> {
                    assertThat(r.reason()).isEqualTo("confusable");
                    assertThat(r.matchedWith()).isEqualTo("admin");
                    assertThat(UsernameAvailabilityService
                            .applyConfusableOverride(r).available()).isTrue();
                })
                .verifyComplete();
    }

    // ── reason=exact (homoglyph/leet collision with an existing username) ─────────

    @Test
    void exactSkeletonCollision_vsExistingUser_isReason_exact() {
        // an existing user "admln" shares the skeleton of the candidate "admiin"
        // (both fold via the leet/collapse pipeline). Use a non-reserved pair so the
        // reserved tier does not pre-empt: existing "joohn" vs candidate "j00hn".
        String candidate = "j00hn";
        String existingSkel = skel.skeleton(candidate);
        when(repo.findBySkeleton(existingSkel))
                .thenReturn(Flux.just(row("john", existingSkel)));

        StepVerifier.create(svc.check(candidate, null))
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.reason()).isEqualTo("exact");
                    assertThat(r.matchedWith()).isEqualTo("john");
                })
                .verifyComplete();
    }

    // ── self-exclusion by EXACT username only ────────────────────────────────────

    @Test
    void selfResave_byExactUsername_isNotAcollision() {
        String skeleton = skel.skeleton("john");
        when(repo.findBySkeleton(skeleton)).thenReturn(Flux.just(row("john", skeleton)));

        // re-checking your OWN username (exact match) is available.
        StepVerifier.create(svc.check("john", "john"))
                .assertNext(r -> assertThat(r.available()).isTrue())
                .verifyComplete();
    }

    @Test
    void differentButConfusableOwner_staysFlagged_despiteSelf() {
        // candidate j00hn shares skeleton with EXISTING user "john"; the caller's
        // OWN username is "jane" (different) -> the confusable "john" still flags.
        String skeleton = skel.skeleton("j00hn");
        when(repo.findBySkeleton(skeleton)).thenReturn(Flux.just(row("john", skeleton)));

        StepVerifier.create(svc.check("j00hn", "jane"))
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.reason()).isEqualTo("exact");
                    assertThat(r.matchedWith()).isEqualTo("john");
                })
                .verifyComplete();
    }

    // ── hard rejects (never folded, no DB hit) ───────────────────────────────────

    @Test
    void mixedScript_isHardReject() {
        StepVerifier.create(svc.check("аdmin", null)) // cyrillic а
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.reason()).isEqualTo("mixed-script");
                    assertThat(r.skeleton()).isNull();
                })
                .verifyComplete();
        verify(repo, never()).findBySkeleton(anyString());
    }

    @Test
    void zeroWidth_isHardReject() {
        StepVerifier.create(svc.check("ad​min", null))
                .assertNext(r -> {
                    assertThat(r.available()).isFalse();
                    assertThat(r.reason()).isEqualTo("zero-width");
                })
                .verifyComplete();
    }

    // ── override rules ───────────────────────────────────────────────────────────

    @Test
    void override_flipsExactAndConfusable_butNeverReservedOrReject() {
        var exact = UsernameAvailabilityDto.collide("x", "exact", "y", "skx");
        var confusable = UsernameAvailabilityDto.collide("x", "confusable", "y", "skx");
        var reserved = UsernameAvailabilityDto.collide("4dmin", "reserved", "admin", "adrnin");
        var reject = UsernameAvailabilityDto.reject("аdmin", "mixed-script");

        assertThat(UsernameAvailabilityService.applyConfusableOverride(exact).available()).isTrue();
        assertThat(UsernameAvailabilityService.applyConfusableOverride(confusable).available()).isTrue();
        // reserved + hard reject are NEVER overridable.
        assertThat(UsernameAvailabilityService.applyConfusableOverride(reserved).available()).isFalse();
        assertThat(UsernameAvailabilityService.applyConfusableOverride(reject).available()).isFalse();
    }

    @Test
    void overrideApplied_detectsVerdictChange() {
        var before = UsernameAvailabilityDto.collide("x", "exact", "y", "skx");
        var after = UsernameAvailabilityService.applyConfusableOverride(before);
        assertThat(UsernameAvailabilityService.overrideApplied(before, after)).isTrue();

        var reserved = UsernameAvailabilityDto.collide("4dmin", "reserved", "admin", "adrnin");
        assertThat(UsernameAvailabilityService.overrideApplied(
                reserved, UsernameAvailabilityService.applyConfusableOverride(reserved))).isFalse();
    }

    // ── registration-grant skeleton write ────────────────────────────────────────

    @Test
    void grant_writesSkeletonRow_withIcuVersion() {
        when(repo.deleteById(anyString())).thenReturn(Mono.empty());
        when(repo.save(any(UsernameSkeleton.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        StepVerifier.create(svc.grant("Charlie", "casdoor-sub-123"))
                .assertNext(r -> {
                    assertThat(r.getUsername()).isEqualTo("charlie"); // lower-cased
                    assertThat(r.getOwnerUserId()).isEqualTo("casdoor-sub-123");
                    assertThat(r.getSkeleton()).isEqualTo(skel.skeleton("charlie"));
                    assertThat(r.getSkeletonIcuVersion()).isEqualTo(UsernameSkeletonService.ICU_VERSION);
                    assertThat(r.getSkeletonFirst()).isEqualTo(skel.skeleton("charlie").substring(0, 1));
                    assertThat(r.isNew()).isTrue();
                })
                .verifyComplete();
        verify(repo).deleteById("charlie");
    }

    @Test
    void grant_skipsBlankUsername() {
        StepVerifier.create(svc.grant("  ", "owner")).verifyComplete();
        verify(repo, never()).save(any());
    }
}
