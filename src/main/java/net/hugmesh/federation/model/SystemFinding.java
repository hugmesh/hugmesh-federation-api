package net.hugmesh.federation.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One SYSTEM-GENERATED moderation finding (table {@code system_findings}).
 *
 * <p>Unlike {@link ModerationRequest} (a HUMAN recommend/refer/decide workflow over
 * federation actions), a system finding is filed AUTOMATICALLY by an upstream edge-AI
 * check — the pre-publish avatar/image vision moderation (user-bff →
 * {@code POST /v1/analyze/content/moderate}). A {@code flag} or {@code reject} verdict
 * produces a finding that lands {@code held} for a human moderator to review.
 *
 * <ul>
 *   <li>{@code reporter}    — always {@code @system} (the automated origin);</li>
 *   <li>{@code subject}     — the Casdoor subject whose content was flagged (the
 *       content owner; server-derived from the producer's JWT, never a body field);</li>
 *   <li>{@code surface}     — where the content was set ({@code profile-avatar}, ...);</li>
 *   <li>{@code disposition} — {@code flagged} (published, queued for review) |
 *       {@code rejected} (blocked at upload);</li>
 *   <li>{@code status}      — {@code held} (awaiting review) | {@code dismissed}
 *       (mod cleared it) | {@code actioned} (mod took action);</li>
 *   <li>classification / confidence / policyHit / perceptualHash — the edge-AI verdict.</li>
 * </ul>
 */
@Table("system_findings")
public class SystemFinding {

    @Id
    private Long id;
    /** Always {@code @system} — the automated origin. Field-initialised so an R2DBC
     *  save (which sends every column, bypassing the DB DEFAULT) never NULLs it. */
    private String reporter = "@system";
    /** The content owner (Casdoor subject) whose image was flagged. */
    private String subject;
    /** Where the content was set: {@code profile-avatar} | ... */
    private String surface;
    /** {@code flagged} | {@code rejected} */
    private String disposition;
    /** {@code safe} | {@code nsfw} | {@code abuse} | {@code unknown} */
    private String classification;
    private Double confidence;
    private Boolean policyHit;
    private String perceptualHash;
    /**
     * OPTIONAL producer-opaque back-reference to the EXACT source row this finding is
     * about — a character-part / sticker id (part-activation correlation, step 1). NULL
     * for the surface-level avatar/profile path (which is about a whole {@code surface},
     * not a single row), so that path is UNAFFECTED. Lets a later moderation -> status
     * reconcile loop address the originating row precisely. Maps to {@code subject_ref}.
     */
    private String subjectRef;
    /** {@code held} | {@code dismissed} | {@code actioned} — the review lifecycle. */
    private String status = "held";
    /** Casdoor subject of the mod/admin who resolved it (null while {@code held}). */
    private String reviewer;
    private Instant ts;
    /**
     * The brand/domain this finding belongs to (multi-tenancy, mirrors
     * {@link ModerationRequest#getDomain()}). Stamped from the producer's
     * issuer-derived scope; a per-domain mod sees ONLY their own brand's findings
     * (SUPERADMIN sees all). Field-initialised to {@code "default"} so an R2DBC save
     * never violates the NOT-NULL column.
     */
    private String domain = "default";

    public Long getId() { return id; }
    public String getReporter() { return reporter; }
    public String getSubject() { return subject; }
    public String getSurface() { return surface; }
    public String getDisposition() { return disposition; }
    public String getClassification() { return classification; }
    public Double getConfidence() { return confidence; }
    public Boolean getPolicyHit() { return policyHit; }
    public String getPerceptualHash() { return perceptualHash; }
    public String getSubjectRef() { return subjectRef; }
    public String getStatus() { return status; }
    public String getReviewer() { return reviewer; }
    public Instant getTs() { return ts; }
    public String getDomain() { return domain; }

    public void setId(Long id) { this.id = id; }
    public void setReporter(String reporter) { this.reporter = reporter; }
    public void setSubject(String subject) { this.subject = subject; }
    public void setSurface(String surface) { this.surface = surface; }
    public void setDisposition(String disposition) { this.disposition = disposition; }
    public void setClassification(String classification) { this.classification = classification; }
    public void setConfidence(Double confidence) { this.confidence = confidence; }
    public void setPolicyHit(Boolean policyHit) { this.policyHit = policyHit; }
    public void setPerceptualHash(String perceptualHash) { this.perceptualHash = perceptualHash; }
    public void setSubjectRef(String subjectRef) { this.subjectRef = subjectRef; }
    public void setStatus(String status) { this.status = status; }
    public void setReviewer(String reviewer) { this.reviewer = reviewer; }
    public void setTs(Instant ts) { this.ts = ts; }
    public void setDomain(String domain) { this.domain = domain; }
}
