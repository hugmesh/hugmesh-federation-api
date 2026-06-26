package systems.snapdragon.federation.model;

import java.time.Instant;

/**
 * Reconciler-facing projection of a RESOLVED {@link SystemFinding} — the exact shape the
 * admin-bff moderation → activation reconciler maps + pushes to user-bff, and nothing
 * more. Deliberately NARROWER than the full {@link SystemFinding} entity: it omits the
 * content owner ({@code subject}), the edge-AI verdict fields ({@code classification} /
 * {@code confidence} / {@code policyHit} / {@code perceptualHash}) and the
 * {@code disposition}, none of which the reconcile loop needs and which an internal
 * service caller should not be handed.
 *
 * <p>Carries exactly:
 * <ul>
 *   <li>{@code id}         — the finding id; ALSO the cursor/watermark (records are
 *       returned id-ASC, so the reconciler advances {@code sinceId} to the max id seen);</li>
 *   <li>{@code surface}    — {@code character-part} | {@code character-sticker} | ...;</li>
 *   <li>{@code subjectRef} — the user-bff row id this finding is about (NON-null by the
 *       reconcile query's {@code subject_ref IS NOT NULL} filter) — the map key;</li>
 *   <li>{@code status}     — {@code actioned} (mod took action) | {@code dismissed}
 *       (mod cleared it) — the outcome to push;</li>
 *   <li>{@code reviewer}   — Casdoor subject of the resolving mod (audit trail);</li>
 *   <li>{@code domain}     — the brand this finding belongs to (the reconciler routes
 *       the push per-domain);</li>
 *   <li>{@code ts}         — when it was resolved.</li>
 * </ul>
 *
 * @see SystemFinding
 */
public record ResolvedFindingView(
        Long id,
        String surface,
        String subjectRef,
        String status,
        String reviewer,
        String domain,
        Instant ts) {

    /** Project a resolved {@link SystemFinding} entity to the reconciler view. */
    public static ResolvedFindingView of(SystemFinding f) {
        return new ResolvedFindingView(
                f.getId(), f.getSurface(), f.getSubjectRef(),
                f.getStatus(), f.getReviewer(), f.getDomain(), f.getTs());
    }
}
