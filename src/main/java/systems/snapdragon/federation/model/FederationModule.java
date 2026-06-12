package systems.snapdragon.federation.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import systems.snapdragon.federation.web.ValidationPatterns;

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

    /**
     * Validation group for the CREATE path ({@code POST /modules}) — the
     * NOT-NULL/required DB columns (slug, display_name, kind, remote_entry_url,
     * version) must be present. It EXTENDS {@link jakarta.validation.groups.Default}
     * so {@code @Validated(OnCreate.class)} also runs the format/enum
     * ({@code @Pattern}/{@code @Size}) constraints (which live in the Default group)
     * — required-ness AND format are both checked on create. The UPDATE path
     * ({@code PUT /modules/{slug}}) is a partial patch (null fields ignored by the
     * service), so it validates only the Default group: format/enum on whatever IS
     * supplied, never required-ness.
     */
    public interface OnCreate extends jakarta.validation.groups.Default {}

    @Id
    private Long id;
    @NotBlank(groups = OnCreate.class, message = "slug is required")
    @Pattern(regexp = ValidationPatterns.SLUG,
            message = "slug must be a DNS-label-style token (lower-alnum + hyphens, 1-128 chars)")
    private String slug;
    @NotBlank(groups = OnCreate.class, message = "displayName is required")
    @Size(max = 1024, message = "displayName must be at most 1024 chars")
    private String displayName;
    /** {@code 'host' | 'remote-shell' | 'remote-game' | 'fragment'} */
    @NotBlank(groups = OnCreate.class, message = "kind is required")
    @Pattern(regexp = ValidationPatterns.MODULE_KIND,
            message = "kind must be host|remote-shell|remote-game|fragment")
    private String kind;
    @NotBlank(groups = OnCreate.class, message = "remoteEntryUrl is required")
    @Size(max = 1024, message = "remoteEntryUrl must be at most 1024 chars")
    private String remoteEntryUrl;
    @Size(max = 1024, message = "exposedModule must be at most 1024 chars")
    private String exposedModule;
    /** NULL = platform/first-party; Casdoor subject for a user-published module. */
    @Size(max = 1024, message = "ownerUserId must be at most 1024 chars")
    private String ownerUserId;
    @NotBlank(groups = OnCreate.class, message = "version is required")
    @Size(max = 1024, message = "version must be at most 1024 chars")
    private String version;
    /** SHA-256 hex of the bundle tree; content-addressed version. */
    @Pattern(regexp = ValidationPatterns.CONTENT_HASH, message = "contentHash must be 64 lower-hex chars")
    private String contentHash;
    /** {@code 'public' | 'internal'} — visibility-filtered in the manifest read path. */
    @Pattern(regexp = ValidationPatterns.VISIBILITY, message = "visibility must be public|internal")
    private String visibility;
    private boolean enabled;
    /** {@code 'closed' | 'open' | 'half'} — kill-switch circuit state. */
    @Pattern(regexp = ValidationPatterns.CIRCUIT_STATE, message = "circuitState must be closed|open|half")
    private String circuitState;
    /** Free-form JSON metadata (integrity hashes, scope flags, dependencies). */
    private String metadata;
    /**
     * The brand/domain this row belongs to (multi-tenancy, changeset 026). Stamped
     * at write time from the principal's issuer-derived {@code DOMAIN_<x>} (NEVER a
     * user-settable claim); a principal only sees/mutates rows in their own domain
     * (SUPERADMIN sees all). DEFAULTs to {@code "default"} so pre-existing rows +
     * single-issuer clusters are unchanged. NOT settable by the API client — the
     * service overwrites it from the authenticated principal on create.
     */
    private String domain = "default";
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
    public String getDomain() { return domain; }
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
    public void setDomain(String domain) { this.domain = domain; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
