package systems.snapdragon.federation.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One row of the dynamic-federation registry (table {@code federation_modules}).
 *
 * <p>Lifted from the snapdragon.games DB-backed federation engine
 * ({@code db/changelog/018} + its {@code FederationModule}), extended with the
 * platform-keystone fields: {@code ownerUserId}, {@code contentHash},
 * {@code visibility}, and {@code circuitState} (the kill-switch state the
 * manifest read path honours).
 *
 * <p>{@code metadata} is a JSON string here: r2dbc has no JSONB codec, so — as in
 * the games engine — the column (a {@code clob}/{@code jsonb}) round-trips as a
 * String and controllers parse it only when they need a flag.
 */
@Table("federation_modules")
public class FederationModule {

    @Id
    private Long id;
    private String slug;
    private String displayName;
    /** {@code 'host' | 'remote-shell' | 'remote-game' | 'fragment'} */
    private String kind;
    private String remoteEntryUrl;
    private String exposedModule;
    /** NULL = platform/first-party; Casdoor subject for a user-published module. */
    private String ownerUserId;
    private String version;
    /** SHA-256 hex of the bundle tree; content-addressed version. */
    private String contentHash;
    /** {@code 'public' | 'internal'} — visibility-filtered in the manifest read path. */
    private String visibility;
    private boolean enabled;
    /** {@code 'closed' | 'open' | 'half'} — kill-switch circuit state. */
    private String circuitState;
    /** Free-form JSON metadata (integrity hashes, scope flags, dependencies). */
    private String metadata;
    private Instant createdAt;
    private Instant updatedAt;

    public Long getId() { return id; }
    public String getSlug() { return slug; }
    public String getDisplayName() { return displayName; }
    public String getKind() { return kind; }
    public String getRemoteEntryUrl() { return remoteEntryUrl; }
    public String getExposedModule() { return exposedModule; }
    public String getOwnerUserId() { return ownerUserId; }
    public String getVersion() { return version; }
    public String getContentHash() { return contentHash; }
    public String getVisibility() { return visibility; }
    public boolean isEnabled() { return enabled; }
    public String getCircuitState() { return circuitState; }
    public String getMetadata() { return metadata; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setId(Long id) { this.id = id; }
    public void setSlug(String slug) { this.slug = slug; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public void setKind(String kind) { this.kind = kind; }
    public void setRemoteEntryUrl(String remoteEntryUrl) { this.remoteEntryUrl = remoteEntryUrl; }
    public void setExposedModule(String exposedModule) { this.exposedModule = exposedModule; }
    public void setOwnerUserId(String ownerUserId) { this.ownerUserId = ownerUserId; }
    public void setVersion(String version) { this.version = version; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    public void setVisibility(String visibility) { this.visibility = visibility; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public void setCircuitState(String circuitState) { this.circuitState = circuitState; }
    public void setMetadata(String metadata) { this.metadata = metadata; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
