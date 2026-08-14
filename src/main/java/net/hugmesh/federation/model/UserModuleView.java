package net.hugmesh.federation.model;

import java.time.Instant;

/**
 * Public-safe projection of a {@link UserModule} bundle row for the bundle METADATA
 * reads ({@code GET /api/federation/bundles/slug/{slug}} and
 * {@code GET /api/federation/bundles/{contentHash}}).
 *
 * <p><b>Why this exists (cross-tenant disclosure fix).</b> Those two reads previously
 * returned the FULL {@link UserModule} entity, leaking the internal storage locator
 * ({@code versionDir} — a {@code file:/...} / {@code s3://...} path) and the owner
 * identity ({@code ownerUserId} — a Casdoor subject / homeserver localpart). Combined
 * with the missing tenant cut that was a cross-tenant metadata IDOR (and a content-
 * hash -> bundle-bytes pivot). This DTO is the NARROW shape those reads now return:
 *
 * <ul>
 *   <li>OMITS {@code versionDir} — the opaque storage locator never goes on the wire;
 *       the remote-fragment SYNC path resolves bytes by content hash server-side
 *       ({@code /bundles/{hash}/files/{*path}}), never from a client-supplied
 *       locator.</li>
 *   <li>OMITS {@code ownerUserId} — the publishing user's identity is not disclosed to
 *       another caller (the owner reads their own bundles via {@code /bundles/mine}).</li>
 *   <li>OMITS {@code domain} / {@code id} — internal bookkeeping; the caller already
 *       knows their own brand, and the row id is not a stable public handle.</li>
 * </ul>
 *
 * <p>It carries the bundle facts a caller legitimately needs to reason about a
 * version: {@code slug}, {@code contentHash} (the sync key), {@code entryFile},
 * {@code manifestJson} (the bundle's own declared manifest), {@code visibility}, and
 * the lifecycle timestamps. Identical to whoever may see the row (the projection
 * itself carries no caller-dependent state — the AUTHZ cut is the domain + owner
 * predicate in {@link net.hugmesh.federation.service.BundleService} that
 * decides WHICH rows reach this projection).
 */
public record UserModuleView(
        String slug,
        String contentHash,
        String entryFile,
        String manifestJson,
        String visibility,
        Instant createdAt,
        Instant supersededAt
) {

    /** Project a bundle row to its public-safe view (drops versionDir + ownerUserId +
     *  domain + id). */
    public static UserModuleView from(UserModule m) {
        return new UserModuleView(
                m.getSlug(),
                m.getContentHash(),
                m.getEntryFile(),
                m.getManifestJson(),
                m.getVisibility(),
                m.getCreatedAt(),
                m.getSupersededAt());
    }
}
