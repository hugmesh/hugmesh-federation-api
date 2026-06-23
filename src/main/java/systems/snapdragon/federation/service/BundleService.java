package systems.snapdragon.federation.service;

import org.springframework.core.io.Resource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.model.UserModuleView;
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.storage.BundleStorage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Bundle storage and lifecycle for per-user federated Angular remote-entry modules,
 * backed by the {@code user_modules} Postgres table.
 *
 * <p>Each bundle is a single file (e.g. {@code remoteEntry.json}) uploaded by an
 * authenticated owner and stored content-addressed on disk via {@link BundleStorage}.
 * The full upload pipeline follows this sequence: receive body bytes → stage to a
 * private temp directory → SHA-256 content-hash the staged tree → install the tree
 * into permanent storage as {@code <slug>/<hash>/<entryFile>} → record a new
 * {@code user_modules} row → stamp {@code superseded_at} on any prior active row for
 * that slug. Only one row per slug per owner is "active" (un-superseded) at a time;
 * old rows remain in the table for history. The full multi-file zip upload pipeline
 * (zip-slip validation, register.sql execution, manifest schema check) is DEFERRED
 * and documented in the README.
 *
 * <p>This service is the storage spine the remote-fragment pods SYNC against:
 * {@link #fetch} by content-hash + relative path is the un-scoped sync-and-serve
 * static read (content-hash acts as an unguessable capability). All other endpoints
 * are domain-scoped and owner-scoped to prevent cross-tenant metadata disclosure.
 *
 * <p><b>Caller-role access matrix</b> (enforced in the QUERY, not in spoofable code):
 * <pre>
 * Endpoint                          SUPERADMIN         ADMIN (per-domain)   USER (per-domain)
 * --------------------------------- -----------------  -------------------  --------------------
 * GET /mine       listForOwner      own rows (any dom) own rows (own dom)   own rows (own dom)
 * GET /slug/{s}   listForSlug       all brands/owners  own brand, any owner own brand, own owner
 * GET /{hash}     byContentHash     all brands/owners  own brand, any owner own brand, own owner
 * PUT /{slug}     put               own rows (any dom) may override owner   own rows (fail-close)
 * GET /slug/{s}/body readOwnBody    any active row     any active row       own active row
 * DELETE /{slug}  deleteForOwner    any active row     any active row       own active row
 * GET /{hash}/f/* fetch             un-scoped (hash as capability)
 * </pre>
 *
 * <p><b>PUT pipeline marble diagram</b> (most complex flow):
 * <pre>
 * body (Flux&lt;DataBuffer&gt;)
 *   |
 *   v
 * stageAndInstall(slug, safeEntry, body)
 *   ├─ [boundedElastic] createTempDirectory("fed-stage-")
 *   ├─ writeStagedBody  ──&gt; reject if entryFile escapes staging dir (400)
 *   └─ installStagedTree
 *        ├─ [boundedElastic] sha256OfTree(staging)  ──&gt; hex hash
 *        └─ [boundedElastic] BundleStorage.installFromStaging(slug, hash, staging)
 *             └─ returns [hash, locator]
 *   |
 *   v
 * insertNewVersion(ownerUserId, slug, ..., [hash, locator])
 *   ├─ supersedePriorOwned
 *   │    ├─ no prior active row   ──&gt; skip (first publish)
 *   │    ├─ prior owned by caller ──&gt; stamp superseded_at, save
 *   │    ├─ prior owned by other + admin ──&gt; stamp superseded_at, save
 *   │    └─ prior owned by other + non-admin ──&gt; 409 CONFLICT (fail-closed)
 *   └─ repo.save(new UserModule)  ──&gt; Mono&lt;UserModule&gt;
 * </pre>
 *
 * @see systems.snapdragon.federation.controller.BundleController
 * @see UserModuleRepository
 * @see UserModule
 * @see UserModuleView
 * @see BundleStorage
 * @see PrincipalDomain
 */
@Service
public class BundleService {

    private final UserModuleRepository repo;
    private final BundleStorage storage;

    public BundleService(UserModuleRepository repo, BundleStorage storage) {
        this.repo = repo;
        this.storage = storage;
    }

    // ----- Owner Listing and Metadata Reads -----

    /**
     * List all {@code user_modules} rows owned by {@code ownerUserId}, across all
     * domains, ordered newest-first. This is the "my bundles" list a caller sees at
     * {@code GET /api/federation/bundles/mine}: the JWT subject is always used as the
     * owner filter (no domain predicate — the caller's own rows are returned regardless
     * of brand, consistent with the caller having one identity across the system).
     *
     * @param ownerUserId the JWT subject whose rows are listed; never {@code null}
     * @return a {@code Flux} emitting every {@link UserModule} owned by this user,
     *         newest-first; empty when the user has published nothing
     */
    public Flux<UserModule> listForOwner(String ownerUserId) {
        return repo.findByOwnerUserIdOrderByCreatedAtDesc(ownerUserId);
    }

    /**
     * List all bundle versions for a given slug — DOMAIN-scoped and OWNER-scoped —
     * projected to the public-safe {@link UserModuleView} (no {@code versionDir} or
     * {@code ownerUserId} fields are exposed). Three access tiers apply:
     *
     * <ul>
     *   <li>SUPERADMIN ({@code scope.superadmin()}) — un-pinned; all brands and all
     *       owners are returned.</li>
     *   <li>per-domain ADMIN ({@code admin=true}) — pinned to their brand; any owner
     *       within that brand is returned.</li>
     *   <li>per-domain non-admin — pinned to their brand AND their own
     *       {@code ownerUserId}, so a caller never enumerates another tenant's or
     *       same-brand peer's bundle metadata.</li>
     * </ul>
     *
     * <p>The previous finder returned the full {@link UserModule} entity for any
     * authenticated caller — a cross-tenant metadata IDOR. The domain + owner cut is
     * enforced in the QUERY, not in spoofable code.
     *
     * @param slug        the module slug to query; rows are returned newest-first
     * @param scope       the caller's domain context; {@code null} resolves to
     *                    {@code "default"} (only relevant for non-superadmin callers)
     * @param ownerUserId the JWT subject used as the owner filter for non-admin callers
     * @param admin       {@code true} when the caller holds a per-domain admin role,
     *                    widening the query to all owners within the domain
     * @return a {@code Flux} of {@link UserModuleView} matching the tier predicate,
     *         newest-first; empty when no rows match (produces no 404 — callers
     *         receive an empty list)
     * @see UserModuleView#from(UserModule)
     */
    public Flux<UserModuleView> listForSlug(String slug, PrincipalDomain scope, String ownerUserId, boolean admin) {
        Flux<UserModule> rows;
        if (scope != null && scope.superadmin()) {
            rows = repo.findBySlugOrderByCreatedAtDesc(slug);
        } else if (admin) {
            rows = repo.findBySlugAndDomainOrderByCreatedAtDesc(slug, domainOf(scope));
        } else {
            rows = repo.findBySlugAndDomainAndOwnerUserIdOrderByCreatedAtDesc(slug, domainOf(scope), ownerUserId);
        }
        return rows.map(UserModuleView::from);
    }

    /**
     * Resolve a single bundle row by content-hash — DOMAIN-scoped and OWNER-scoped —
     * projected to the public-safe {@link UserModuleView}. The same three access tiers
     * as {@link #listForSlug} apply: a hash that belongs to another brand (or, for a
     * non-admin, another owner) resolves EMPTY and is converted to 404, closing the
     * cross-tenant metadata IDOR and the content-hash-to-bytes pivot. The remote-fragment
     * SYNC byte fetch remains un-scoped — see {@link #fetch}.
     *
     * @param contentHash the SHA-256 hex hash identifying the bundle version to look up
     * @param scope       the caller's domain context; {@code null} resolves to
     *                    {@code "default"} (only relevant for non-superadmin callers)
     * @param ownerUserId the JWT subject used as the owner filter for non-admin callers
     * @param admin       {@code true} when the caller holds a per-domain admin role,
     *                    widening the query to all owners within the domain
     * @return a {@code Mono} emitting the matching {@link UserModuleView}; empty when no
     *         row matches the tier predicate, which the controller converts to 404
     * @throws ResponseStatusException 404 when no bundle row matches the hash within the
     *                                 caller's permitted scope
     * @see #fetch(String, String)
     */
    public Mono<UserModuleView> byContentHash(String contentHash, PrincipalDomain scope,
                                              String ownerUserId, boolean admin) {
        Mono<UserModule> row;
        if (scope != null && scope.superadmin()) {
            row = repo.findByContentHash(contentHash);
        } else if (admin) {
            row = repo.findByContentHashAndDomain(contentHash, domainOf(scope));
        } else {
            row = repo.findByContentHashAndDomainAndOwnerUserId(contentHash, domainOf(scope), ownerUserId);
        }
        return row
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no bundle: " + contentHash)))
                .map(UserModuleView::from);
    }

    // ----- Bundle Write (PUT) -----

    /**
     * Publish or replace a single-file module bundle for the given slug. The uploaded
     * body is staged to a private temp directory, SHA-256 content-hashed, installed via
     * the {@link BundleStorage} strategy as {@code <slug>/<hash>/<entryFile>}, recorded
     * as a new active row in {@code user_modules}, and any prior active row for the slug
     * is superseded. All blocking filesystem work runs on {@code boundedElastic} so the
     * WebFlux event loop stays clean.
     *
     * <p>OWNER-SCOPED (fail-closed): a slug's active version is a per-owner resource.
     * If the slug already has an active row owned by a DIFFERENT user, a non-admin PUT
     * is rejected with 409 BEFORE any supersede or insert runs, so an attacker cannot
     * displace a victim's active card by PUTting to their slug (the victim's row is
     * left completely untouched). An {@code admin} caller may supersede the active row
     * regardless of its owner.
     *
     * @param ownerUserId  the JWT subject that will own the new bundle row; stamped into
     *                     the {@code owner_user_id} column — never taken from a request param
     * @param slug         the module slug to publish under; must be non-blank (400 if absent)
     * @param entryFile    the relative filename stored inside the bundle directory
     *                     (e.g. {@code remoteEntry.json}); defaults to
     *                     {@code remoteEntry.json} when blank
     * @param visibility   the visibility label stamped on the row (e.g. {@code "internal"});
     *                     defaults to {@code "internal"} when {@code null}
     * @param manifestJson a JSON string stored in the {@code manifest_json} column;
     *                     defaults to {@code "{}"} when {@code null}
     * @param admin        {@code true} when the caller holds a per-domain admin role,
     *                     allowing supersede of rows owned by other users
     * @param scope        the caller's domain context; the {@code domain} column is
     *                     stamped from this — NEVER from a request param; a SUPERADMIN
     *                     scope stamps {@code "default"}
     * @param body         the reactive stream of uploaded file bytes to stage and install
     * @return a {@code Mono} emitting the newly saved {@link UserModule} row on success
     * @throws ResponseStatusException 400 when {@code slug} is blank, or when
     *                                 {@code entryFile} resolves to a path that escapes
     *                                 the staging directory (zip-slip-style traversal)
     * @throws ResponseStatusException 409 when the slug already has an active row owned
     *                                 by a different user and the caller is not an admin
     * @see #stageAndInstall(String, String, Flux)
     * @see #insertNewVersion(String, String, String, String, String, boolean, PrincipalDomain, String[])
     */
    public Mono<UserModule> put(String ownerUserId, String slug, String entryFile,
                                String visibility, String manifestJson, boolean admin,
                                PrincipalDomain scope, Flux<DataBuffer> body) {
        if (slug == null || slug.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "slug required"));
        }
        String safeEntry = (entryFile == null || entryFile.isBlank()) ? "remoteEntry.json" : entryFile;
        // Linear pipeline (was a 3-level nested lambda):
        //   1. stage the body to a temp dir + content-hash + install -> [hash, locator],
        //   2. owner-scoped supersede (fail-closed) then insert the new active row.
        return stageAndInstall(slug, safeEntry, body)
                .flatMap(hl -> insertNewVersion(
                        ownerUserId, slug, safeEntry, visibility, manifestJson, admin, scope, hl));
    }

    // ----- Bundle Read (Sync + Body) -----

    /**
     * Fetch a file from a bundle by content-hash — the remote-fragment SYNC read used
     * by fragment pods to retrieve static assets. This finder is un-scoped (no domain or
     * owner predicate): the content-hash itself acts as an unguessable capability, and
     * the pod performing the sync already holds the hash from the manifest it received
     * through the domain-scoped manifest path. The file at {@code relativePath} is read
     * from the installed bundle directory and streamed back to the caller.
     *
     * @param contentHash  the SHA-256 hex hash identifying the bundle version; used as
     *                     an unguessable capability (un-scoped by design)
     * @param relativePath the relative path within the bundle directory to read
     *                     (e.g. {@code remoteEntry.json})
     * @return a {@code Mono} emitting the {@link Resource} for the requested file
     * @throws ResponseStatusException 404 when no bundle row matches the content-hash,
     *                                 or when the file at {@code relativePath} is absent
     *                                 from storage
     */
    public Mono<Resource> fetch(String contentHash, String relativePath) {
        return repo.findByContentHash(contentHash)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no bundle: " + contentHash)))
                .flatMap(m -> Mono.fromCallable(() -> storage.read(m.getVersionDir(), relativePath))
                        .subscribeOn(Schedulers.boundedElastic()))
                .flatMap(res -> res == null
                        ? Mono.error(new ResponseStatusException(NOT_FOUND, "no file: " + relativePath))
                        : Mono.just(res));
    }

    /**
     * Read the caller's own current card body by slug — the entry-file bytes of the
     * caller's active (non-superseded) bundle for that slug. This is the
     * read-my-card-body endpoint the user-bff proxies so the WYSIWYG editor can
     * pre-fill for an Edit operation. Owner-scoped: only the row owned by
     * {@code ownerUserId} is resolved unless the caller is an admin, in which case
     * the slug's active row is returned regardless of owner.
     *
     * @param ownerUserId the JWT subject whose active bundle row is resolved
     * @param slug        the module slug to read the active body for
     * @param admin       {@code true} when the caller holds a per-domain admin role,
     *                    allowing read of the active row regardless of owner
     * @return a {@code Mono} emitting the {@link Resource} for the entry-file bytes
     *         of the active bundle row
     * @throws ResponseStatusException 404 when the caller has no active bundle for the
     *                                 slug, or when the entry file is gone from storage
     * @see #activeRowForCaller(String, String, boolean)
     */
    public Mono<Resource> readOwnBody(String ownerUserId, String slug, boolean admin) {
        return activeRowForCaller(ownerUserId, slug, admin)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no body for slug: " + slug)))
                // read the active row's entry-file bytes (or 404 if the file is gone)
                .flatMap(m -> readEntryFileOr404(m, slug));
    }

    // ----- Bundle Delete -----

    /**
     * Delete the caller's own current bundle for a slug. Finds the caller's active
     * (non-superseded) {@code user_modules} row, removes its content-addressed version
     * directory from {@link BundleStorage}, and stamps {@code superseded_at} on the row
     * so history stays queryable — the slug simply has no active version afterwards.
     * Owner-scoped: only the caller's own active row is touched unless the caller is an
     * admin, in which case the slug's active row is removed regardless of owner.
     *
     * <p>A delete of another user's card surfaces as 404 to a non-admin caller (never
     * as a cross-tenant delete), because the owner-scoped active-row finder returns
     * empty for a row the caller does not own.
     *
     * @param ownerUserId the JWT subject whose active bundle row is resolved for deletion
     * @param slug        the module slug whose active bundle should be deleted
     * @param admin       {@code true} when the caller holds a per-domain admin role,
     *                    allowing deletion of the active row regardless of owner
     * @return a {@code Mono<Void>} that completes when the storage version has been
     *         removed and the row has been marked superseded
     * @throws ResponseStatusException 404 when the caller has no active bundle for the
     *                                 slug (includes the case where another user owns the
     *                                 active row and the caller is not an admin)
     * @see #activeRowForCaller(String, String, boolean)
     */
    public Mono<Void> deleteForOwner(String ownerUserId, String slug, boolean admin) {
        return activeRowForCaller(ownerUserId, slug, admin)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no bundle for slug: " + slug)))
                .flatMap(m -> Mono.fromRunnable(() -> storage.deleteVersion(m.getVersionDir()))
                        .subscribeOn(Schedulers.boundedElastic())
                        .then(Mono.defer(() -> {
                            m.setSupersededAt(Instant.now());
                            return repo.save(m);
                        })))
                .then();
    }

    // ----- Pipeline Stages -----

    /**
     * Stage the uploaded body to a private temp directory, content-hash the staged tree,
     * and install it via the {@link BundleStorage} strategy. Returns {@code [hash, locator]}
     * where {@code hash} is the SHA-256 hex digest and {@code locator} is the storage
     * path returned by {@link BundleStorage#installFromStaging}. Path-traversal is
     * rejected (the resolved entry must remain under the staging directory) BEFORE any
     * byte is written. All blocking filesystem work runs on {@code boundedElastic} so the
     * WebFlux event loop stays clean.
     *
     * @param slug      the module slug, passed through to {@link BundleStorage#installFromStaging}
     * @param safeEntry the already-validated relative entry filename (e.g. {@code remoteEntry.json})
     * @param body      the reactive stream of uploaded file bytes
     * @return a {@code Mono} emitting {@code [hash, locator]} on successful staging and
     *         installation
     * @throws ResponseStatusException 400 when {@code safeEntry} resolves to a path that
     *                                 escapes the staging directory
     */
    private Mono<String[]> stageAndInstall(String slug, String safeEntry, Flux<DataBuffer> body) {
        return Mono.fromCallable(() -> Files.createTempDirectory("fed-stage-"))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(staging -> writeStagedBody(staging, safeEntry, body)
                        .then(installStagedTree(slug, staging)));
    }

    /**
     * Write the body bytes to {@code <staging>/<safeEntry>}, rejecting an entry filename
     * that would escape the staging directory (zip-slip-style traversal) before any byte
     * is written.
     *
     * @param staging   the temporary staging directory
     * @param safeEntry the relative entry filename to write under {@code staging}
     * @param body      the reactive byte stream to write
     * @return a {@code Mono<Void>} that completes when all bytes have been written
     * @throws ResponseStatusException 400 when the resolved target path escapes
     *                                 {@code staging}
     */
    private static Mono<Void> writeStagedBody(Path staging, String safeEntry, Flux<DataBuffer> body) {
        Path target = staging.resolve(safeEntry).normalize();
        if (!target.startsWith(staging)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "entryFile escapes bundle"));
        }
        return DataBufferUtils.write(body, target).then();
    }

    /**
     * Content-hash the staged tree and install it as {@code <slug>/<hash>/...} via
     * {@link BundleStorage#installFromStaging}, returning {@code [hash, locator]}.
     * Blocking filesystem work runs on {@code boundedElastic}.
     *
     * @param slug    the module slug used to name the install destination
     * @param staging the staging directory whose contents are hashed and installed
     * @return a {@code Mono} emitting {@code [hash, locator]} where {@code hash} is the
     *         SHA-256 hex digest of the staged tree and {@code locator} is the storage
     *         path returned by {@link BundleStorage#installFromStaging}
     */
    private Mono<String[]> installStagedTree(String slug, Path staging) {
        return Mono.fromCallable(() -> {
            String hash = sha256OfTree(staging);
            String locator = storage.installFromStaging(slug, hash, staging);
            return new String[]{hash, locator};
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Owner-scoped supersede (fail-closed: a cross-owner PUT is rejected with 409
     * BEFORE the new row is assembled) then insert the new active {@code user_modules}
     * row from {@code hl = [hash, locator]}. The {@code domain} column is stamped from
     * the authenticated scope — NEVER from a request param — so a SUPERADMIN publish
     * lands in {@code "default"} (mirrors ModuleRegistryService.domainForWrite).
     *
     * @param ownerUserId  the JWT subject stamped as the new row's owner
     * @param slug         the module slug for the new row
     * @param safeEntry    the entry filename stored in the {@code entry_file} column
     * @param visibility   the visibility label stored in the {@code visibility} column;
     *                     defaults to {@code "internal"} when {@code null}
     * @param manifestJson the JSON string stored in {@code manifest_json}; defaults to
     *                     {@code "{}"} when {@code null}
     * @param admin        {@code true} when the caller may supersede rows owned by others
     * @param scope        the caller's domain context; the {@code domain} column is
     *                     stamped from this via {@link #domainForWrite(PrincipalDomain)}
     * @param hl           a two-element array {@code [hash, locator]} from
     *                     {@link #stageAndInstall}
     * @return a {@code Mono} emitting the newly saved {@link UserModule} row
     * @throws ResponseStatusException 409 when the slug has an active row owned by a
     *                                 different user and the caller is not an admin
     */
    private Mono<UserModule> insertNewVersion(String ownerUserId, String slug, String safeEntry,
                                              String visibility, String manifestJson, boolean admin,
                                              PrincipalDomain scope, String[] hl) {
        String hash = hl[0];
        String locator = hl[1];
        return supersedePriorOwned(ownerUserId, slug, admin)
                .then(Mono.defer(() -> {
                    UserModule m = new UserModule();
                    m.setOwnerUserId(ownerUserId);
                    m.setSlug(slug);
                    m.setVersionDir(locator);
                    m.setEntryFile(safeEntry);
                    m.setContentHash(hash);
                    m.setManifestJson(manifestJson == null ? "{}" : manifestJson);
                    m.setVisibility(visibility == null ? "internal" : visibility);
                    m.setDomain(domainForWrite(scope));
                    m.setCreatedAt(Instant.now());
                    return repo.save(m);
                }));
    }

    // ----- Helpers -----

    /**
     * The active row the caller may read or delete: an admin gets the slug's active row
     * regardless of owner; a normal user gets ONLY their own active row (so a non-owner
     * sees an empty {@code Mono} which the caller converts to 404, never another user's
     * bundle).
     *
     * @param ownerUserId the JWT subject used as the owner filter for non-admin callers
     * @param slug        the module slug whose active row is resolved
     * @param admin       {@code true} when the owner filter should be bypassed
     * @return a {@code Mono} emitting the matching active {@link UserModule}, or empty
     *         when no active row exists within the caller's permitted scope
     */
    private Mono<UserModule> activeRowForCaller(String ownerUserId, String slug, boolean admin) {
        return admin
                ? repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(slug)
                : repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(slug, ownerUserId);
    }

    /**
     * Supersede the slug's current active row on behalf of {@code ownerUserId},
     * owner-scoped and fail-closed:
     * <ul>
     *   <li>no active row for the slug — nothing to supersede (a first publish);</li>
     *   <li>active row owned by the caller (or the caller is {@code admin}) —
     *       stamp {@code superseded_at}, save, then the new version is inserted;</li>
     *   <li>active row owned by ANOTHER user and the caller is not admin —
     *       error 409 BEFORE any write, so a cross-owner PUT can never displace
     *       the victim's active card (their row is left untouched).</li>
     * </ul>
     * The conflict check uses the slug-only active finder and compares the row's owner
     * against the JWT subject (the same owner-equals-subject rule that read and delete
     * enforce). We do NOT rely on the owner-scoped finder alone, because a missing
     * own-row would otherwise silently fall through to a first-publish and leave a rival
     * owner's active row in place (two active rows for one slug).
     *
     * @param ownerUserId the JWT subject performing the PUT
     * @param slug        the module slug whose active row is superseded
     * @param admin       {@code true} when the caller may supersede rows owned by others
     * @return a {@code Mono<Void>} that completes when the prior active row (if any) has
     *         been stamped superseded and saved
     * @throws ResponseStatusException 409 when the slug has an active row owned by a
     *                                 different user and the caller is not an admin
     */
    private Mono<Void> supersedePriorOwned(String ownerUserId, String slug, boolean admin) {
        return repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(slug)
                .flatMap(prior -> {
                    if (!admin && !ownerUserId.equals(prior.getOwnerUserId())) {
                        return Mono.<UserModule>error(new ResponseStatusException(
                                CONFLICT, "slug already has an active bundle owned by another user"));
                    }
                    prior.setSupersededAt(Instant.now());
                    return repo.save(prior);
                })
                .then();
    }

    /**
     * Read the entry-file bytes of a {@code user_modules} row, or signal 404 when the
     * entry file is gone from storage. {@code storage.read} returns {@code null} for a
     * missing file, so the result is wrapped in an {@link java.util.Optional} — Reactor
     * would otherwise silently drop a {@code null} emission into {@code onComplete} (an
     * empty {@code Mono}), masking the missing-file case as an unexpected empty stream.
     * Blocking read runs on {@code boundedElastic}.
     *
     * @param m    the active {@link UserModule} row whose entry file should be read
     * @param slug the slug string used only in the 404 error message for diagnostics
     * @return a {@code Mono} emitting the {@link Resource} for the entry-file bytes
     * @throws ResponseStatusException 404 when the entry file is absent from storage
     */
    private Mono<Resource> readEntryFileOr404(UserModule m, String slug) {
        String entry = (m.getEntryFile() == null || m.getEntryFile().isBlank())
                ? "remoteEntry.json" : m.getEntryFile();
        return Mono.fromCallable(() -> java.util.Optional.ofNullable(storage.read(m.getVersionDir(), entry)))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(opt -> opt
                        .<Mono<Resource>>map(Mono::just)
                        .orElseGet(() -> Mono.error(
                                new ResponseStatusException(NOT_FOUND, "no body for slug: " + slug))));
    }

    /**
     * The domain to pin a metadata read query to: the caller's domain from {@code scope},
     * or {@code "default"} when no scope is supplied. Never {@code null} — a per-domain
     * scope always carries a domain string (a failed resolve produces {@code NO_DOMAIN},
     * which matches nothing in the database).
     *
     * @param scope the caller's domain context; may be {@code null} for scope-less callers
     * @return the domain string to use as a query predicate
     */
    private static String domainOf(PrincipalDomain scope) {
        return scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    /**
     * The domain to STAMP on a written bundle row: the principal's domain from
     * {@code scope}, or {@code "default"} for a SUPERADMIN or scope-less write. NEVER
     * taken from a request parameter — the domain column is always derived from the
     * authenticated principal (mirrors ModuleRegistryService.domainForWrite).
     *
     * @param scope the caller's domain context; may be {@code null} for scope-less callers
     * @return the domain string to stamp into the {@code domain} column of the new row
     */
    private static String domainForWrite(PrincipalDomain scope) {
        return (scope != null && scope.superadmin()) ? PrincipalDomain.forDomain("default").domain() : domainOf(scope);
    }

    /**
     * Compute a SHA-256 digest over the sorted regular-file contents of a directory tree
     * and return the result as a lowercase hex string. Each file contributes its
     * relative path string (as bytes) followed by its full contents to the digest, in
     * lexicographic path order, so the hash is stable across identical content regardless
     * of filesystem ordering.
     *
     * @param dir the root directory to hash
     * @return the SHA-256 hex digest of the tree's contents
     * @throws IOException when any file under {@code dir} cannot be read
     */
    private static String sha256OfTree(Path dir) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (var files = Files.walk(dir)) {
                files.filter(Files::isRegularFile).sorted().forEach(p -> {
                    try {
                        // feed relative path first so two files with identical bytes but
                        // different names produce different hashes
                        md.update(dir.relativize(p).toString().getBytes());
                        md.update(Files.readAllBytes(p));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append("%02x".formatted(b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
