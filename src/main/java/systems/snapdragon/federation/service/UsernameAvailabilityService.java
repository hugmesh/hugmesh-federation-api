package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.UsernameAvailabilityDto;
import systems.snapdragon.federation.model.UsernameSkeleton;
import systems.snapdragon.federation.repository.UsernameSkeletonRepository;
import systems.snapdragon.federation.service.UsernameSkeletonService.ConfusableException;

import java.time.Instant;
import java.util.Locale;

/**
 * The username availability / confusable CHECK + the registration-grant skeleton
 * write — the registry-owned engine behind
 * {@code /api/federation/username/{candidate}/availability}.
 *
 * <h2>Match tiers (a candidate collides if ANY holds)</h2>
 * <ol type="a">
 *   <li>{@code skeleton(candidate) == skeleton(existingUser)} — indexed equality
 *       over {@code username_skeleton} (homoglyph / leet: {@code adm1n ~ admin}).
 *       Self-exclusion is by EXACT username only — a different-but-confusable owner
 *       stays flagged.</li>
 *   <li>{@code skeleton(candidate)} is in the precomputed reserved-skeleton set
 *       ({@code 4dmin ~ admin}, {@code v4ult ~ vault}). NEVER overridable.</li>
 *   <li>the length-scaled Damerau / edit-distance typo-squat tier vs the reserved
 *       set (and the affix anti-impersonation rule) — both in
 *       {@link UsernameSkeletonService#matchedReserved}.</li>
 * </ol>
 *
 * <h2>Hard rejects (reason {@code mixed-script} / {@code zero-width} / {@code empty})</h2>
 * A candidate carrying a zero-width / bidi splice or a mixed-script confusable is
 * rejected BEFORE any DB lookup — it must never be minted, regardless of collision.
 *
 * <h2>Override</h2>
 * {@code override=confusable} (ROLE_ADMIN only, audited by the controller) flips a
 * {@code reason=confusable}/{@code exact} verdict to available — but NEVER a
 * {@code reason=reserved} or a hard reject. The reserved rule + the exact-username
 * DB backstop are not weakened.
 */
@Service
public class UsernameAvailabilityService {

    private final UsernameSkeletonService skeletons;
    private final UsernameSkeletonRepository repo;

    public UsernameAvailabilityService(UsernameSkeletonService skeletons,
                                       UsernameSkeletonRepository repo) {
        this.skeletons = skeletons;
        this.repo = repo;
    }

    /**
     * Check a candidate, excluding the caller's OWN existing username (by EXACT
     * username equality only — never by skeleton-owner, so a confusable of a
     * different owner is still flagged). {@code self} may be null (registration of a
     * brand-new identity).
     */
    public Mono<UsernameAvailabilityDto> check(String candidate, String self) {
        final String raw = candidate == null ? "" : candidate.trim();
        final String selfLc = self == null ? null : self.trim().toLowerCase(Locale.ROOT);

        // Hard rejects first — a zero-width / bidi / mixed-script candidate must
        // never mint, independent of any collision.
        final String skel;
        try {
            skel = skeletons.skeleton(raw);
        } catch (ConfusableException ex) {
            return Mono.just(UsernameAvailabilityDto.reject(raw, ex.reason()));
        }

        // (b)+(c)+(d) reserved tiers — computed off the precomputed set, no DB hit.
        // Reserved is checked BEFORE the user collision so a reserved-confusable is
        // always reason=reserved (and never overridable).
        String reservedMatch = skeletons.matchedReserved(raw);
        if (reservedMatch != null) {
            return Mono.just(UsernameAvailabilityDto.collide(raw, "reserved", reservedMatch, skel));
        }

        // (a) EXACT-skeleton collision vs existing usernames (indexed equality).
        // Self-exclusion is by EXACT username equality only.
        return repo.findBySkeleton(skel)
                .filter(row -> selfLc == null
                        || !selfLc.equals(row.getUsername().toLowerCase(Locale.ROOT)))
                .next()
                .map(row -> {
                    // Same EXACT skeleton => homoglyph/leet collision (reason=exact).
                    return UsernameAvailabilityDto.collide(raw, "exact", row.getUsername(), skel);
                })
                .defaultIfEmpty(UsernameAvailabilityDto.available(raw, skel));
    }

    /**
     * Apply the ROLE_ADMIN {@code override=confusable} verdict to a check result:
     * a {@code reason=exact} or {@code reason=confusable} collision becomes
     * available; a {@code reason=reserved} or a hard reject is NEVER overridable.
     * The caller (controller) writes the audit row when this actually changes the
     * verdict.
     */
    public static UsernameAvailabilityDto applyConfusableOverride(UsernameAvailabilityDto result) {
        if (result.available()) {
            return result;
        }
        String reason = result.reason();
        if ("exact".equals(reason) || "confusable".equals(reason)) {
            return UsernameAvailabilityDto.available(result.candidate(), result.skeleton());
        }
        // reserved / mixed-script / zero-width / empty are never overridable.
        return result;
    }

    /** Whether an override actually changed the verdict (drives the audit row). */
    public static boolean overrideApplied(UsernameAvailabilityDto before, UsernameAvailabilityDto after) {
        return before.collide() && after.available();
    }

    /**
     * Mint (upsert) the skeleton row for a granted username — called in the SAME
     * flow that mints {@code slug=profile-<username>} and on a registration grant.
     * Idempotent for re-grants of the same username (delete-then-insert keeps the
     * skeleton + ICU version current if the fold ever shifts). Hard-reject inputs
     * are skipped (they could never have been granted).
     */
    public Mono<UsernameSkeleton> grant(String username, String ownerUserId) {
        final String uname = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        if (uname.isEmpty()) {
            return Mono.empty();
        }
        final String skel;
        try {
            skel = skeletons.skeleton(uname);
        } catch (ConfusableException ex) {
            // Should never happen for a granted username (the gate rejected it), but
            // never throw on the mint path — just skip the cache row.
            return Mono.empty();
        }
        String first = skel.isEmpty() ? "" : skel.substring(0, 1);
        UsernameSkeleton row = new UsernameSkeleton(
                uname, ownerUserId, skel, first,
                UsernameSkeletonService.ICU_VERSION, Instant.now());
        // Natural-key upsert: remove any prior row for this username, then insert
        // (Persistable.isNew()=true forces an INSERT for the natural PK).
        return repo.deleteById(uname).then(repo.save(row.markNew()));
    }
}
