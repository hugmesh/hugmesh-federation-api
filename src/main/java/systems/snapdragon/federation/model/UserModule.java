package systems.snapdragon.federation.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One per-user federated-module bundle upload (table {@code user_modules}).
 *
 * <p>Mirror of the games engine's {@code game_uploads}: the bookkeeping for a
 * content-hash-versioned bundle a user published. {@code versionDir} holds the
 * opaque {@code BundleStorage} locator; the remote-fragment pods sync the bundle
 * by {@code contentHash}.
 */
@Table("user_modules")
public class UserModule {

    @Id
    private Long id;
    private String ownerUserId;
    private String slug;
    /** Opaque {@code BundleStorage} locator ({@code file:/...} or {@code s3://...}). */
    private String versionDir;
    /**
     * Relative filename of the bundle's entry file inside {@code versionDir} (the
     * single source file the card editor authored; default {@code remoteEntry.json}).
     * Persisted so the owner can RE-READ the card's current body bytes by slug.
     */
    private String entryFile;
    /** SHA-256 hex of the bundle tree; the sync key + version. */
    private String contentHash;
    /** Bundle manifest JSON (round-trips as a String — no r2dbc JSONB codec). */
    private String manifestJson;
    /** {@code 'public' | 'internal'} */
    private String visibility;
    private Instant createdAt;
    private Instant supersededAt;

    public Long getId() { return id; }
    public String getOwnerUserId() { return ownerUserId; }
    public String getSlug() { return slug; }
    public String getVersionDir() { return versionDir; }
    public String getEntryFile() { return entryFile; }
    public String getContentHash() { return contentHash; }
    public String getManifestJson() { return manifestJson; }
    public String getVisibility() { return visibility; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getSupersededAt() { return supersededAt; }

    public void setId(Long id) { this.id = id; }
    public void setOwnerUserId(String ownerUserId) { this.ownerUserId = ownerUserId; }
    public void setSlug(String slug) { this.slug = slug; }
    public void setVersionDir(String versionDir) { this.versionDir = versionDir; }
    public void setEntryFile(String entryFile) { this.entryFile = entryFile; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    public void setManifestJson(String manifestJson) { this.manifestJson = manifestJson; }
    public void setVisibility(String visibility) { this.visibility = visibility; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setSupersededAt(Instant supersededAt) { this.supersededAt = supersededAt; }
}
