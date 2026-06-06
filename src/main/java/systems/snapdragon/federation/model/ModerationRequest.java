package systems.snapdragon.federation.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One moderation workflow item (table {@code moderation_requests}).
 *
 * <p>The recommend / refer / decide flow: a mod recommends or refers an action,
 * an admin decides. Mirrors the games {@code ModerationController}'s
 * ROLE_MOD-recommends / ROLE_ADMIN-decides split, lifted to the platform.
 */
@Table("moderation_requests")
public class ModerationRequest {

    @Id
    private Long id;
    private String requester;
    /** {@code 'instance-block' | 'user-removal'} */
    private String kind;
    private String target;
    private String reason;
    /** {@code 'recommended' | 'referred' | 'approved' | 'denied'} */
    private String status;
    private String modReferrer;
    private String adminDecider;
    private Instant ts;

    public Long getId() { return id; }
    public String getRequester() { return requester; }
    public String getKind() { return kind; }
    public String getTarget() { return target; }
    public String getReason() { return reason; }
    public String getStatus() { return status; }
    public String getModReferrer() { return modReferrer; }
    public String getAdminDecider() { return adminDecider; }
    public Instant getTs() { return ts; }

    public void setId(Long id) { this.id = id; }
    public void setRequester(String requester) { this.requester = requester; }
    public void setKind(String kind) { this.kind = kind; }
    public void setTarget(String target) { this.target = target; }
    public void setReason(String reason) { this.reason = reason; }
    public void setStatus(String status) { this.status = status; }
    public void setModReferrer(String modReferrer) { this.modReferrer = modReferrer; }
    public void setAdminDecider(String adminDecider) { this.adminDecider = adminDecider; }
    public void setTs(Instant ts) { this.ts = ts; }
}
