package systems.hugmesh.federation.model;

/**
 * The result of a username availability / confusable check
 * ({@code GET /api/federation/username/{candidate}/availability}).
 *
 * <p><b>INTERNAL / ROLE_SERVICE only.</b> {@code matchedWith} is an enumeration
 * oracle (it names the colliding username / reserved label), so this DTO is never
 * returned on a public surface — only to an internal service caller. A SPA-facing
 * variant (if one is ever added) must drop {@code matchedWith} and rate-limit.
 *
 * @param candidate   the (trimmed) candidate username as supplied.
 * @param available   true iff the candidate may be minted (no collision, not reserved).
 * @param collide     true iff a collision / reserved / hard-reject was found
 *                    (always {@code !available}, kept explicit for the caller).
 * @param reason      machine reason: {@code exact} (homoglyph/leet collision with an
 *                    existing username), {@code confusable} (look-alike of another
 *                    user via the edit/affix tiers), {@code reserved} (collides with a
 *                    reserved label or its skeleton), {@code mixed-script} /
 *                    {@code zero-width} / {@code empty} (hard-reject — never folded),
 *                    or {@code null} when available.
 * @param matchedWith the colliding username or reserved label (null when available
 *                    or on a hard-reject). ENUMERATION ORACLE — internal only.
 * @param skeleton    the computed confusable skeleton (null on a hard-reject).
 */
public record UsernameAvailabilityDto(
        String candidate,
        boolean available,
        boolean collide,
        String reason,
        String matchedWith,
        String skeleton) {

    /** Available — no collision, not reserved. */
    public static UsernameAvailabilityDto available(String candidate, String skeleton) {
        return new UsernameAvailabilityDto(candidate, true, false, null, null, skeleton);
    }

    /** A collision / reserved match (reason + matchedWith populated). */
    public static UsernameAvailabilityDto collide(String candidate, String reason,
                                                  String matchedWith, String skeleton) {
        return new UsernameAvailabilityDto(candidate, false, true, reason, matchedWith, skeleton);
    }

    /** A hard reject (mixed-script / zero-width / empty) — never folded, no skeleton. */
    public static UsernameAvailabilityDto reject(String candidate, String reason) {
        return new UsernameAvailabilityDto(candidate, false, true, reason, null, null);
    }
}
