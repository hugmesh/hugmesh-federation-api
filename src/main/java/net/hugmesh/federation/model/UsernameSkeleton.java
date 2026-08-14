package net.hugmesh.federation.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One minted username's confusable SKELETON (table {@code username_skeleton},
 * changeset 020). Written in the SAME flow that mints {@code slug=profile-<username>}
 * and on a registration grant, so the look-alike collision check ({@code adm1n ~
 * admin}, Cyrillic {@code а}dmin ~ admin) has an indexed equality lookup.
 *
 * <h2>{@code username} is the natural PK (NOT auto-generated)</h2>
 * The username is the primary key; there is no surrogate id. R2DBC's {@code save()}
 * decides insert-vs-update by {@code @Id} nullness, which never works for a natural
 * key (a fresh row already carries its PK). This entity therefore implements
 * {@link Persistable} with an explicit {@link #isNew()} flag so a registration mint
 * is always an INSERT — mirroring the same convention used for natural-keyed R2DBC
 * rows.
 *
 * <h2>The skeleton is a RECOMPUTABLE CACHE, never a unique identity</h2>
 * {@code skeleton} is stored under a NON-unique index ({@code ix_username_skeleton_skel})
 * alongside {@code skeletonIcuVersion} (the ICU version that produced it). It is a
 * derived view of {@code username} — fully recomputable — so an icu4j upgrade is
 * handled by a re-index migration, never by a failed UNIQUE constraint. The real DB
 * backstop stays the existing slug UNIQUE column + the 017 reserved CHECK.
 */
@Table("username_skeleton")
public class UsernameSkeleton implements Persistable<String> {

    @Id
    private String username;
    private String ownerUserId;
    /** The canonical confusable skeleton (NON-unique index). Recomputable cache. */
    private String skeleton;
    /** First char of the skeleton — a cheap pre-filter / bucket column. */
    private String skeletonFirst;
    /** The ICU version that produced {@code skeleton} (drift / re-index gate). */
    private String skeletonIcuVersion;
    private Instant createdAt;

    /** Transient insert/update discriminator for the natural-key PK (see class doc). */
    @Transient
    private boolean isNew;

    public UsernameSkeleton() {}

    public UsernameSkeleton(String username, String ownerUserId, String skeleton,
                            String skeletonFirst, String skeletonIcuVersion, Instant createdAt) {
        this.username = username;
        this.ownerUserId = ownerUserId;
        this.skeleton = skeleton;
        this.skeletonFirst = skeletonFirst;
        this.skeletonIcuVersion = skeletonIcuVersion;
        this.createdAt = createdAt;
    }

    @Override
    public String getId() {
        return username;
    }

    @Override
    @Transient
    public boolean isNew() {
        return isNew;
    }

    /** Mark this row as a fresh INSERT (a registration mint). */
    public UsernameSkeleton markNew() {
        this.isNew = true;
        return this;
    }

    public String getUsername() { return username; }
    public String getOwnerUserId() { return ownerUserId; }
    public String getSkeleton() { return skeleton; }
    public String getSkeletonFirst() { return skeletonFirst; }
    public String getSkeletonIcuVersion() { return skeletonIcuVersion; }
    public Instant getCreatedAt() { return createdAt; }

    public void setUsername(String username) { this.username = username; }
    public void setOwnerUserId(String ownerUserId) { this.ownerUserId = ownerUserId; }
    public void setSkeleton(String skeleton) { this.skeleton = skeleton; }
    public void setSkeletonFirst(String skeletonFirst) { this.skeletonFirst = skeletonFirst; }
    public void setSkeletonIcuVersion(String skeletonIcuVersion) { this.skeletonIcuVersion = skeletonIcuVersion; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
