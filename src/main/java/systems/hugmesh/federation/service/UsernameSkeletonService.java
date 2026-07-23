package systems.hugmesh.federation.service;

import com.ibm.icu.text.Bidi;
import com.ibm.icu.text.SpoofChecker;
import org.apache.commons.text.similarity.LongestCommonSubsequenceDistance;
import org.springframework.stereotype.Service;
import systems.hugmesh.federation.controller.ReservedNames;

import java.text.Normalizer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Canonical USERNAME / displayName CONFUSABLE skeleton — the look-alike fold that
 * powers registration-time uniqueness ({@code adm1n ~ admin}, {@code rooot ~ root},
 * Cyrillic {@code а}dmin ~ admin) and the reserved-confusable backstop.
 *
 * <h2>The skeleton is a RECOMPUTABLE CACHE, never a unique DB identity</h2>
 * The {@link SpoofChecker#getSkeleton confusable skeleton} is NOT stable across ICU
 * releases. The {@code username_skeleton} row (changeset 020) stores it under a
 * NON-unique index next to the ICU version that produced it; the real DB backstop
 * stays the existing {@code slug} UNIQUE column + the 017 / 004 reserved CHECKs.
 * Every icu4j bump is gated behind a re-index migration (recompute + re-check all
 * skeletons in one transaction). Never derive a UNIQUE constraint from a skeleton.
 *
 * <h2>Canonical fold order (do NOT reorder — each step assumes the prior one)</h2>
 * <ol>
 *   <li><b>lowercase + trim</b> ({@link Locale#ROOT}).</li>
 *   <li><b>REJECT</b> (never silently strip) any candidate carrying a default-ignorable
 *       / format (Cf) / zero-width ({@code U+200B–200D}, {@code U+FEFF}) / bidi-control
 *       ({@code U+202A–202E}, {@code U+2066–2069}) code point — BEFORE any folding, so a
 *       zero-width / bidi splice can never sneak two distinct rows past the equality
 *       check ({@link ConfusableException} with reason {@code zero-width}).</li>
 *   <li><b>NFKD</b> normalize + strip combining marks (category {@code Mn}) — folds
 *       full-width / compatibility forms + diacritics ({@code Á → a}).</li>
 *   <li><b>ICU {@link SpoofChecker}</b> with {@code CONFUSABLE | RESTRICTION_LEVEL}
 *       at {@code MODERATELY_RESTRICTIVE}: REJECT a mixed-script / non-conformant
 *       candidate outright ({@link ConfusableException} reason {@code mixed-script}),
 *       then {@code getSkeleton} for the homoglyph fold ({@code getBidiSkeleton} on a
 *       RTL-capable surface — see {@link #displaySkeleton}).</li>
 *   <li><b>ASCII leet / homoglyph map</b> applied AFTER ICU:
 *       {@code 0→o, 1→l→i, 5→s, 3→e, 4→a, 7→t, 8→b, 9→g, 2→z, |→i, $→s, @→a}.
 *       {@code rn→m} and {@code vv→w} are DELIBERATELY DROPPED (documented ICU
 *       over-blockers — they false-positive real names).</li>
 *   <li><b>strip separators</b> — delete {@code - _ . space}.</li>
 *   <li><b>collapse runs of length ≥3</b> (NOT ≥2) so {@code anna / matt / sass}
 *       survive while {@code rooot→root}, {@code aaadmin→admin} still collide.</li>
 * </ol>
 *
 * <p>Cost is ~5–10ms on the cold (registration) path only; the read path uses the
 * precomputed reserved-skeleton {@link Set} (O(1) membership, no recompute).
 */
@Service
public class UsernameSkeletonService {

    /** The pinned ICU version stamped into every {@code username_skeleton} row. */
    public static final String ICU_VERSION = com.ibm.icu.util.VersionInfo.ICU_VERSION.toString();

    /** Minimum run length that gets collapsed. ≥3 keeps anna/matt; rooot still folds. */
    static final int COLLAPSE_MIN_RUN = 3;

    /**
     * ASCII leet / homoglyph fold applied AFTER the ICU skeleton (and after the ICU
     * output is re-lowercased — ICU emits mixed-case canonical forms, e.g.
     * {@code 0 → O}). ICU's own confusable table already folds {@code 0→o} (via
     * {@code O}), {@code 1→l}, {@code |→l}, and {@code m→rn}; this map then folds the
     * residual leet digits ICU leaves untouched ({@code 2,3,4,5,7,8,9}) plus
     * {@code $→s}, {@code @→a}, and — completing the design's {@code 1→l→i} chain —
     * {@code l→i} (so both a literal {@code l} and ICU's {@code 1→l} land on
     * {@code i}). {@code rn→m} and {@code vv→w} are DELIBERATELY ABSENT (documented
     * ICU over-blockers); note ICU itself folds {@code m→rn}, which is internally
     * consistent (every {@code m} on BOTH the candidate and reserved side becomes
     * {@code rn}) and is NOT reversed here.
     */
    private static final Map<Character, Character> LEET = Map.ofEntries(
            Map.entry('0', 'o'), Map.entry('1', 'i'), Map.entry('5', 's'),
            Map.entry('3', 'e'), Map.entry('4', 'a'), Map.entry('7', 't'),
            Map.entry('8', 'b'), Map.entry('9', 'g'), Map.entry('2', 'z'),
            Map.entry('|', 'i'), Map.entry('$', 's'), Map.entry('@', 'a'),
            // l -> i completes 1 -> l -> i (ICU already mapped 1 and | to l).
            Map.entry('l', 'i'));

    /** Separators deleted by {@code stripSeparators}. */
    private static final Set<Character> SEPARATORS = Set.of('-', '_', '.', ' ');

    /**
     * The Damerau-ish edit distance for the typo-squat tier. commons-text ships
     * {@code LongestCommonSubsequenceDistance}; the reserved-set typo tier scales the
     * threshold by length, so LCS distance (insert/delete, transposition-tolerant
     * for the short reserved labels) is a sound, cheap surrogate that never blocks.
     */
    private static final LongestCommonSubsequenceDistance EDIT = new LongestCommonSubsequenceDistance();

    /**
     * A confusable SpoofChecker is immutable + thread-safe once built, so one shared
     * instance serves every request. CONFUSABLE drives getSkeleton; RESTRICTION_LEVEL
     * (MODERATELY_RESTRICTIVE) drives the mixed-script rejection in {@link #checks}.
     */
    private final SpoofChecker spoof = new SpoofChecker.Builder()
            .setChecks(SpoofChecker.CONFUSABLE | SpoofChecker.RESTRICTION_LEVEL)
            .setRestrictionLevel(SpoofChecker.RestrictionLevel.MODERATELY_RESTRICTIVE)
            .build();

    /** PRECOMPUTED reserved-label skeletons (class-load-once). The READ layer keys
     *  off this set with O(1) membership and never recomputes. */
    private final Set<String> reservedSkeletons;
    /** Reserved skeleton -> the (lower-cased) reserved label that produced it, for
     *  {@code matchedWith} reporting. First writer wins on a (rare) skeleton clash. */
    private final Map<String, String> reservedSkeletonToLabel;

    public UsernameSkeletonService() {
        Map<String, String> byLabel = new HashMap<>();
        for (String label : ReservedNames.RESERVED_LABELS) {
            String skel = skeletonOrNull(label);
            // A reserved label folds cleanly (ASCII); if one ever didn't (mixed-script
            // / zero-width — impossible for the curated set) it simply isn't indexed.
            if (skel != null && !skel.isBlank()) {
                byLabel.putIfAbsent(skel, label.toLowerCase(Locale.ROOT));
            }
        }
        this.reservedSkeletonToLabel = Map.copyOf(byLabel);
        this.reservedSkeletons = Set.copyOf(byLabel.keySet());

        // Fold each anti-impersonation affix through the SAME skeleton so it
        // compares against an already-folded candidate skeleton (official ->
        // officiai under the l->i fold, istrator -> istrator, 01 -> oi, ...).
        Set<String> affixes = new HashSet<>();
        for (String raw : RAW_IMPERSONATION_AFFIXES) {
            String folded = skeletonOrNull(raw);
            if (folded != null && !folded.isBlank()) {
                affixes.add(folded);
            }
        }
        this.impersonationAffixes = Set.copyOf(affixes);
    }

    // ── public surface ──────────────────────────────────────────────────────────

    /**
     * The canonical confusable skeleton of a username candidate. Throws
     * {@link ConfusableException} (reason {@code zero-width} or {@code mixed-script})
     * for a candidate that must be rejected outright rather than folded.
     */
    public String skeleton(String candidate) {
        return computeSkeleton(candidate, false);
    }

    /**
     * The displayName skeleton — identical pipeline but using ICU
     * {@code getBidiSkeleton} (RTL-capable surface). The username surface is
     * ASCII-only today, but displayName is free UTF-8, so the bidi fold matters
     * there (the displayName guard lives in user-bff; this method is the shared
     * primitive it calls).
     */
    public String displaySkeleton(String candidate) {
        return computeSkeleton(candidate, true);
    }

    /** The precomputed reserved-label skeletons (O(1) membership; READ-layer gate). */
    public Set<String> reservedSkeletons() {
        return reservedSkeletons;
    }

    /** True iff the candidate's skeleton equals a reserved-label skeleton
     *  (e.g. {@code 4dmin / akk0ma / v4ult}). Rejected unconditionally — never an
     *  override target. Returns false for a candidate that fails the hard checks
     *  (callers handle the {@link ConfusableException} separately). */
    public boolean isReservedConfusable(String candidate) {
        String skel = skeletonOrNull(candidate);
        return skel != null && reservedSkeletons.contains(skel);
    }

    /** True iff a RAW reserved-label string's skeleton is in the reserved set — the
     *  O(1) check the READ layer (VanityController) runs on the first DNS label with
     *  NO DB hit. Tolerant of a non-foldable input (returns false). */
    public boolean isReservedSkeleton(String label) {
        return isReservedConfusable(label);
    }

    /**
     * A reserved-set match tagged with the TIER that produced it — so the caller can
     * apply the correct override policy:
     * <ul>
     *   <li>{@code exact=true} — the candidate's skeleton IS a reserved-label skeleton
     *       (tier b, e.g. {@code 4dmin ~ admin}, {@code v4ult ~ vault}). A genuine
     *       confusable of a reserved label; NEVER overridable ({@code reason=reserved}).</li>
     *   <li>{@code exact=false} — a fuzzy length-scaled typo-squat or affix
     *       anti-impersonation match (tiers c/d, e.g. {@code administrator},
     *       {@code admin01}). Heuristic and prone to false positives on legitimate
     *       names, so ROLE_ADMIN-overridable ({@code reason=confusable}).</li>
     * </ul>
     * {@code label} is the reserved label matched.
     */
    public record ReservedMatch(String label, boolean exact) {}

    /**
     * The reserved label a candidate collides with, tagged with WHICH tier matched
     * (see {@link ReservedMatch}), or {@code null} if the candidate is clear of the
     * reserved set. The exact reserved-skeleton tier (b) is never overridable; the
     * fuzzy typo-squat / affix tiers (c/d) are ROLE_ADMIN-overridable. Returns
     * {@code null} (not an exception) on a non-foldable candidate — the caller invokes
     * {@link #skeleton} first to surface the hard rejection.
     */
    public ReservedMatch matchReserved(String candidate) {
        String skel = skeletonOrNull(candidate);
        if (skel == null || skel.isBlank()) {
            return null;
        }
        // (b) exact reserved-skeleton membership — a genuine confusable, never overridable.
        String exact = reservedSkeletonToLabel.get(skel);
        if (exact != null) {
            return new ReservedMatch(exact, true);
        }
        // (c) length-scaled typo-squat distance vs the reserved-skeleton set +
        // (d) the affix anti-impersonation rule, both against the curated set only.
        // Heuristic tiers -> overridable (reason=confusable), per the controller contract.
        int budget = typoBudget(skel.length());
        for (Map.Entry<String, String> e : reservedSkeletonToLabel.entrySet()) {
            String reservedSkel = e.getKey();
            if (affixImpersonates(skel, reservedSkel) || EDIT.apply(skel, reservedSkel) <= budget) {
                return new ReservedMatch(e.getValue(), false);
            }
        }
        return null;
    }

    /**
     * The reserved label whose skeleton a candidate collides with via ANY
     * anti-impersonation tier (exact reserved skeleton, the length-scaled typo-squat
     * distance, or the affix rule), or {@code null} if the candidate is clear of the
     * reserved set. Back-compat string view of {@link #matchReserved} (drops the tier
     * tag); prefer {@code matchReserved} when the override policy depends on the tier.
     */
    public String matchedReserved(String candidate) {
        ReservedMatch m = matchReserved(candidate);
        return m == null ? null : m.label();
    }

    /** Whether two non-null skeletons are an EXACT confusable match (the user-vs-user
     *  tier — equality only; collapse + the fold already absorb typo-squats). */
    public boolean sameSkeleton(String a, String b) {
        return a != null && a.equals(b);
    }

    // ── the fold ─────────────────────────────────────────────────────────────────

    /** Compute-or-null wrapper that swallows the hard-rejection exception (used by
     *  the reserved-set precompute + the membership probes that must not throw). */
    private String skeletonOrNull(String candidate) {
        try {
            return computeSkeleton(candidate, false);
        } catch (ConfusableException ex) {
            return null;
        }
    }

    private String computeSkeleton(String candidate, boolean bidi) {
        if (candidate == null) {
            throw new ConfusableException("empty", "candidate is null");
        }
        // 1. lowercase + trim (ROOT locale — never Turkish-i folding).
        String s = candidate.trim().toLowerCase(Locale.ROOT);
        if (s.isEmpty()) {
            throw new ConfusableException("empty", "candidate is blank");
        }
        // 2. REJECT (do not strip) zero-width / bidi-control / format (Cf) /
        //    default-ignorable code points BEFORE any folding.
        rejectIgnorables(s);
        // 3. NFKD + strip combining marks (Mn).
        s = stripCombiningMarks(Normalizer.normalize(s, Normalizer.Form.NFKD));
        if (s.isEmpty()) {
            throw new ConfusableException("empty", "folds to empty");
        }
        // 4. ICU restriction-level check (reject mixed-script) + confusable skeleton.
        if (spoof.failsChecks(s)) {
            throw new ConfusableException("mixed-script",
                    "candidate is mixed-script / non-conformant under MODERATELY_RESTRICTIVE");
        }
        s = bidi ? spoof.getBidiSkeleton(Bidi.RTL, s) : spoof.getSkeleton(s);
        // ICU emits mixed-case canonical forms (0 -> O, etc.); re-lowercase so the
        // leet map + equality compare on a single case (ROOT — no Turkish-i).
        s = s.toLowerCase(Locale.ROOT);
        // 5. ASCII leet / homoglyph map (after ICU; rn->m & vv->w deliberately absent).
        s = leetMap(s);
        // 6. strip separators (- _ . space).
        s = stripSeparators(s);
        // 7. collapse runs of length >= 3.
        s = collapseRepeats(s);
        return s;
    }

    /** Throw if the string carries a zero-width / bidi-control / format (Cf) /
     *  default-ignorable code point (the pre-ICU bypass guard). */
    private static void rejectIgnorables(String s) {
        // Reject each code point that is a disallowed zero-width / bidi / format character.
        s.codePoints().forEach(UsernameSkeletonService::rejectIfIgnorable);
    }

    /** Throw a {@link ConfusableException} when {@code cp} is a disallowed invisible code point. */
    private static void rejectIfIgnorable(int cp) {
        int type = Character.getType(cp);
        if (type == Character.FORMAT // Cf — zero-width joiner/non-joiner, bidi controls, BOM, ...
                || Character.isIdentifierIgnorable(cp)
                || (cp >= 0x200B && cp <= 0x200F)   // zero-width space/(non-)joiner + LRM/RLM
                || cp == 0xFEFF                       // BOM / zero-width no-break space
                || (cp >= 0x202A && cp <= 0x202E)   // bidi embedding/override
                || (cp >= 0x2066 && cp <= 0x2069)) { // bidi isolates
            throw new ConfusableException("zero-width",
                    "disallowed zero-width / bidi / format code point U+%04X".formatted(cp));
        }
    }

    private static String stripCombiningMarks(String s) {
        StringBuilder out = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> {
            if (Character.getType(cp) != Character.NON_SPACING_MARK) { // Mn
                out.appendCodePoint(cp);
            }
        });
        return out.toString();
    }

    private static String leetMap(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append(LEET.getOrDefault(c, c));
        }
        return out.toString();
    }

    private static String stripSeparators(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!SEPARATORS.contains(c)) {
                out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * Collapse any run of the SAME char with length &gt;= {@link #COLLAPSE_MIN_RUN}
     * down to length 2; runs of length 1 or 2 ({@code anna}, {@code matt},
     * {@code sass}) are emitted verbatim. Capping at 2 (NOT 1) is what makes the
     * design's two collapse examples BOTH hold: {@code rooot}({@code ooo→oo})
     * folds to EXACTLY {@code root} (run of 2 stays), so a triple-letter typo-squat
     * of a reserved {@code root} collides via exact skeleton equality, while a
     * genuine double like {@code anna} is untouched. Longer pads
     * ({@code aaadmin→aadmin}) then land on the reserved {@code admin} via the
     * length-scaled typo-squat tier. Collapsing to 1 would instead make
     * {@code rooot→rot != root} and miss the design's stated collision.
     */
    static String collapseRepeats(String s) {
        if (s.length() < COLLAPSE_MIN_RUN) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            int j = i + 1;
            while (j < s.length() && s.charAt(j) == c) {
                j++;
            }
            int run = j - i;
            // run of 1 or 2 -> verbatim; run >= 3 -> capped at 2.
            out.append(c);
            if (run >= 2) {
                out.append(c);
            }
            i = j;
        }
        return out.toString();
    }

    // ── reserved-set tiers ───────────────────────────────────────────────────────

    /** Length-scaled typo-squat budget: 0 for len<=3, 1 for 4-7, 2 for >=8. */
    static int typoBudget(int len) {
        if (len <= 3) return 0;
        if (len <= 7) return 1;
        return 2;
    }

    /**
     * Anti-impersonation affix tokens (RAW). A candidate whose skeleton is a
     * reserved skeleton wrapped in one of these official-sounding affixes
     * ({@code admin-official}, {@code officialadmin}, {@code administrator},
     * {@code admin01}) is treated as a reserved collision. Kept small + anchored to
     * the reserved token at a boundary so it bounds false positives (a reserved
     * skeleton appearing mid-word — e.g. {@code badminton} containing {@code admin}
     * — is NOT matched). These RAW tokens are folded through the SAME skeleton at
     * construction ({@link #impersonationAffixes}) so they compare against the
     * already-folded candidate skeleton ({@code official → officiai} under l→i).
     */
    private static final Set<String> RAW_IMPERSONATION_AFFIXES = Set.of(
            "official", "team", "support", "staff", "istrator", "1", "01");

    /** {@link #RAW_IMPERSONATION_AFFIXES} folded through the skeleton (so they match
     *  a candidate skeleton, e.g. {@code official → officiai}). */
    private final Set<String> impersonationAffixes;

    boolean affixImpersonates(String skel, String reservedSkel) {
        if (reservedSkel.length() < 3) {
            return false; // too short to anchor an affix rule without flooding FPs.
        }
        // reserved + affix  (adminofficial; administrator -> adrnin + istrator).
        if (skel.length() > reservedSkel.length() && skel.startsWith(reservedSkel)) {
            String suffix = skel.substring(reservedSkel.length());
            if (impersonationAffixes.contains(suffix)) {
                return true;
            }
        }
        // affix + reserved  (officialadmin).
        if (skel.length() > reservedSkel.length() && skel.endsWith(reservedSkel)) {
            String prefix = skel.substring(0, skel.length() - reservedSkel.length());
            return impersonationAffixes.contains(prefix);
        }
        return false;
    }

    /**
     * Hard-rejection signal: a candidate that must NOT be folded into a skeleton at
     * all (a zero-width / bidi splice or a mixed-script confusable). Distinct from a
     * fold-then-collide outcome. Carries a machine reason ({@code zero-width} |
     * {@code mixed-script} | {@code empty}) the availability endpoint surfaces.
     */
    public static final class ConfusableException extends RuntimeException {
        private final String reason;

        public ConfusableException(String reason, String message) {
            super(message);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }
}
