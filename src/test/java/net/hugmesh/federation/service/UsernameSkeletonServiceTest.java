package net.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import net.hugmesh.federation.service.UsernameSkeletonService.ConfusableException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit coverage for the canonical confusable SKELETON fold — the heart of the
 * registration-time uniqueness + look-alike rejection. Exercises each design
 * requirement directly (no Spring context; the service is dependency-free).
 */
class UsernameSkeletonServiceTest {

    private final UsernameSkeletonService svc = new UsernameSkeletonService();

    // ── leet / homoglyph folding: confusables share a skeleton ───────────────────

    /**
     * Each leet / separator / case / pad variant of a reserved label must fold to
     * the SAME skeleton as the label, so it is caught as a confusable. (The exact
     * skeleton string is ICU-version-dependent; we assert EQUALITY to the canonical
     * fold, not a literal value.)
     */
    @ParameterizedTest
    @CsvSource({
            "admin,  adm1n",   // 1 -> i (via ICU 1->l, leet l->i)
            "admin,  4dmin",   // 4 -> a
            "admin,  Admin",   // case
            "admin,  ad-min",  // separator
            "admin,  ad.min",  // separator
            "admin,  ad_min",  // separator
            "admin,  aaadmin", // collapse >=3 then typo tier (skeletons differ but both collide on reserved)
            "root,   r00t",    // 0 -> o
            "root,   rooot",   // collapse ooo -> oo == root
            "vault,  v4ult",   // 4 -> a
    })
    void confusableVariantsFoldToward_reservedLabel(String canonical, String variant) {
        // adm1n/4dmin/etc fold to EXACTLY the reserved label's skeleton; the padded
        // aaadmin folds to a DIFFERENT skeleton but is still a reserved match (tier c)
        // — that distinction is asserted in the matchedReserved tests below. Here we
        // assert the exact-equality cases.
        if (!variant.equals("aaadmin")) {
            assertThat(svc.skeleton(variant)).isEqualTo(svc.skeleton(canonical));
        }
        // In all cases the variant collides with the reserved label.
        assertThat(svc.matchedReserved(variant)).isEqualTo(reservedLower(canonical));
    }

    private static String reservedLower(String label) {
        return label; // the reserved-label values used here are already lower-case.
    }

    // ── collapse runs >= 3 (anna / matt survive; rooot -> root collides) ──────────

    @Test
    void collapse_keepsDoubles_butFoldsTriplesPlus() {
        // genuine doubles are preserved (distinct skeletons, NOT collapsed away).
        assertThat(svc.skeleton("anna")).isEqualTo("anna");
        assertThat(svc.skeleton("sass")).isEqualTo("sass");
        // anna != ana (collapse does NOT touch a run of 2).
        assertThat(svc.skeleton("anna")).isNotEqualTo(svc.skeleton("ana"));
        // a triple+ run collapses to 2, so rooot folds to EXACTLY root.
        assertThat(svc.skeleton("rooot")).isEqualTo(svc.skeleton("root"));
    }

    @Test
    void collapseRepeats_unit_capsRunsAtTwo() {
        assertThat(UsernameSkeletonService.collapseRepeats("rooot")).isEqualTo("root");
        assertThat(UsernameSkeletonService.collapseRepeats("aaa")).isEqualTo("aa");
        assertThat(UsernameSkeletonService.collapseRepeats("anna")).isEqualTo("anna");
        assertThat(UsernameSkeletonService.collapseRepeats("aaaa")).isEqualTo("aa");
        assertThat(UsernameSkeletonService.collapseRepeats("ab")).isEqualTo("ab");
    }

    // ── mixed-script rejection (Cyrillic look-alike) ─────────────────────────────

    @Test
    void mixedScript_isRejected_notFolded() {
        // 'аdmin' with a CYRILLIC 'а' (U+0430) is mixed-script under
        // MODERATELY_RESTRICTIVE -> hard reject (reason mixed-script), never folded.
        String cyrillicAdmin = "аdmin";
        assertThatThrownBy(() -> svc.skeleton(cyrillicAdmin))
                .isInstanceOf(ConfusableException.class)
                .satisfies(e -> assertThat(((ConfusableException) e).reason()).isEqualTo("mixed-script"));
    }

    // ── zero-width / bidi rejection (pre-ICU bypass guard) ───────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "ad​min",   // zero-width space
            "ad‌min",   // zero-width non-joiner (Cf)
            "ad‍min",   // zero-width joiner (Cf)
            "ad﻿min",   // BOM / zero-width no-break space
            "ad‮min",   // RLO bidi override
            "ad⁦min",   // LRI bidi isolate
    })
    void zeroWidthOrBidi_isRejected_beforeFolding(String candidate) {
        assertThatThrownBy(() -> svc.skeleton(candidate))
                .isInstanceOf(ConfusableException.class)
                .satisfies(e -> assertThat(((ConfusableException) e).reason()).isEqualTo("zero-width"));
    }

    @Test
    void blankOrNull_isRejected() {
        assertThatThrownBy(() -> svc.skeleton(null)).isInstanceOf(ConfusableException.class);
        assertThatThrownBy(() -> svc.skeleton("   ")).isInstanceOf(ConfusableException.class);
    }

    // ── reserved-skeleton set + tiers ────────────────────────────────────────────

    @Test
    void reservedSkeletonSet_isPrecomputed_andNonEmpty() {
        assertThat(svc.reservedSkeletons()).isNotEmpty();
        // 'admin' and 'matrix' are reserved -> their skeletons are in the set.
        assertThat(svc.reservedSkeletons()).contains(svc.skeleton("admin"), svc.skeleton("matrix"));
    }

    @Test
    void isReservedConfusable_exactSkeletonTier() {
        assertThat(svc.isReservedConfusable("4dmin")).isTrue();   // ~ admin
        assertThat(svc.isReservedConfusable("v4ult")).isTrue();   // ~ vault
        assertThat(svc.isReservedConfusable("r00t")).isTrue();    // ~ root
        assertThat(svc.isReservedConfusable("alice")).isFalse();  // a real username
        assertThat(svc.isReservedConfusable("bob")).isFalse();
    }

    @Test
    void matchedReserved_typoSquatTier_vsReservedSet() {
        // aaadmin folds to aadmin-ish -> within the length-scaled edit budget of admin.
        assertThat(svc.matchedReserved("aaadmin")).isEqualTo("admin");
        // administrator -> admin via the affix / edit tier.
        assertThat(svc.matchedReserved("administrator")).isEqualTo("admin");
    }

    @Test
    void matchedReserved_affixImpersonationTier() {
        assertThat(svc.matchedReserved("admin-official")).isEqualTo("admin");
        assertThat(svc.matchedReserved("officialadmin")).isEqualTo("admin");
        assertThat(svc.matchedReserved("admin01")).isEqualTo("admin");
    }

    @Test
    void matchedReserved_doesNotOverBlock_midWordContainment() {
        // 'badminton' contains 'admin' mid-word but is NOT an impersonation.
        assertThat(svc.matchedReserved("badminton")).isNull();
        // a genuine, unrelated username is clear of the reserved set.
        assertThat(svc.matchedReserved("alice")).isNull();
        assertThat(svc.matchedReserved("charlie")).isNull();
    }

    @Test
    void typoBudget_isLengthScaled() {
        assertThat(UsernameSkeletonService.typoBudget(2)).isZero();
        assertThat(UsernameSkeletonService.typoBudget(3)).isZero();
        assertThat(UsernameSkeletonService.typoBudget(4)).isEqualTo(1);
        assertThat(UsernameSkeletonService.typoBudget(7)).isEqualTo(1);
        assertThat(UsernameSkeletonService.typoBudget(8)).isEqualTo(2);
        assertThat(UsernameSkeletonService.typoBudget(20)).isEqualTo(2);
    }

    // ── sameSkeleton (user-vs-user equality tier) ────────────────────────────────

    @Test
    void sameSkeleton_isExactEquality() {
        assertThat(svc.sameSkeleton(svc.skeleton("adm1n"), svc.skeleton("admin"))).isTrue();
        assertThat(svc.sameSkeleton(svc.skeleton("anna"), svc.skeleton("ana"))).isFalse();
        assertThat(svc.sameSkeleton(null, "x")).isFalse();
    }

    // ── ICU version is stamped (re-index gate) ───────────────────────────────────

    @Test
    void icuVersion_isExposed_forTheReindexGate() {
        assertThat(UsernameSkeletonService.ICU_VERSION).isNotBlank();
    }

    // ── displaySkeleton (bidi surface) folds too ─────────────────────────────────

    @Test
    void displaySkeleton_foldsAscii_andRejectsZeroWidth() {
        assertThat(svc.displaySkeleton("Admin")).isEqualTo(svc.displaySkeleton("admin"));
        assertThatThrownBy(() -> svc.displaySkeleton("ad​min"))
                .isInstanceOf(ConfusableException.class);
    }
}
