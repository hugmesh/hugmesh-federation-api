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
 * Bundle storage + lifecycle for per-user federated modules ({@code user_modules}).
 *
 * <p>Mirrors the games upload pipeline shape (stage -> content-hash ->
 * {@link BundleStorage#installFromStaging} -> row insert -> supersede prior
 * version) but at single-file granularity here: the full multi-file zip upload
 * pipeline (zip-slip validation, register.sql execution, manifest schema check)
 * is DEFERRED and documented in the README. This service is the storage spine
 * the remote-fragment pods SYNC against: {@link #fetch} by content-hash +
 * relative path is the sync-and-serve-static read.
 */
@Service
public class BundleService {

    private final UserModuleRepository repo;
    private final BundleStorage storage;

    public BundleService(UserModuleRepository repo, BundleStorage storage) {
        this.repo = repo;
        this.storage = storage;
    }

    public Flux<UserModule> listForOwner(String ownerUserId) {
        return repo.findByOwnerUserIdOrderByCreatedAtDesc(ownerUserId);
    }

    /**
     * List a slug's bundle versions — DOMAIN-scoped + OWNER-scoped, projected to the
     * public-safe {@link UserModuleView} (no {@code versionDir} / {@code ownerUserId}).
     * Three tiers (mirrors ModuleRegistryService / readOwnBody):
     *
     * <ul>
     *   <li>SUPERADMIN — un-pinned, every brand, every owner.</li>
     *   <li>per-domain ADMIN — pinned to their brand, any owner in it.</li>
     *   <li>per-domain NON-admin — pinned to their brand AND their ownership, so a
     *       caller never enumerates another tenant's (or a same-brand peer's) bundle
     *       metadata.</li>
     * </ul>
     *
     * The previous {@code permitAll}-ish (.authenticated()-only, no cut) finder
     * returned the FULL entity for ANY caller — a cross-tenant metadata IDOR. The cut
     * is enforced in the QUERY, not in spoofable code.
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
     * Resolve a bundle by content-hash — DOMAIN-scoped + OWNER-scoped, projected to the
     * public-safe {@link UserModuleView}. Same three tiers as {@link #listForSlug}. A
     * hash that belongs to another brand (or, for a non-admin, another owner) resolves
     * EMPTY -> 404, closing the cross-tenant metadata IDOR + the content-hash -> bytes
     * pivot. (The remote-fragment SYNC byte FETCH stays un-scoped — see {@link #fetch}.)
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

    /** The domain to pin a metadata read to: the caller's domain, or {@code "default"}
     *  when no scope is supplied. Never null for a per-domain scope (failed resolve =>
     *  NO_DOMAIN, matches nothing). */
    private static String domainOf(PrincipalDomain scope) {
        return scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    /** The domain to STAMP on a written bundle row: the principal's domain, or
     *  {@code "default"} for a SUPERADMIN / scope-less write. NEVER taken from a
     *  request param (mirrors ModuleRegistryService.domainForWrite). */
    private static String domainForWrite(PrincipalDomain scope) {
        return (scope != null && scope.superadmin()) ? PrincipalDomain.forDomain("default").domain() : domainOf(scope);
    }

    /**
     * PUT a single-file module bundle. The body is staged, SHA-256-hashed into
     * the version (content-addressed), installed via the {@link BundleStorage}
     * strategy as {@code <slug>/<hash>/<entryFile>}, recorded in
     * {@code user_modules}, and any prior active row for the slug is superseded.
     *
     * <p>{@code entryFile} is the relative filename inside the bundle dir (e.g.
     * {@code remoteEntry.json}). Blocking filesystem work is wrapped on
     * boundedElastic to keep the WebFlux event loop clean.
     *
     * <p>OWNER-SCOPED (mirrors read/delete): a slug's active version is a
     * per-owner resource, so a PUT may only supersede an active row the CALLER
     * owns. If the slug already has an active row owned by ANOTHER user, a
     * non-admin PUT is rejected with 409 BEFORE any supersede/insert runs (a
     * fail-closed short-circuit), so an attacker can never displace a victim's
     * active card by PUTting to their slug. An {@code admin} caller may supersede
     * the slug's active row regardless of owner (the admin-override flow).
     */
    public Mono<UserModule> put(String ownerUserId, String slug, String entryFile,
                                String visibility, String manifestJson, boolean admin,
                                PrincipalDomain scope, Flux<DataBuffer> body) {
        if (slug == null || slug.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "slug required"));
        }
        String safeEntry = (entryFile == null || entryFile.isBlank()) ? "remoteEntry.json" : entryFile;
        return Mono.fromCallable(() -> Files.createTempDirectory("fed-stage-"))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(staging -> {
                    Path target = staging.resolve(safeEntry).normalize();
                    if (!target.startsWith(staging)) {
                        return Mono.error(new ResponseStatusException(BAD_REQUEST, "entryFile escapes bundle"));
                    }
                    return DataBufferUtils.write(body, target)
                            .then(Mono.fromCallable(() -> {
                                String hash = sha256OfTree(staging);
                                String locator = storage.installFromStaging(slug, hash, staging);
                                return new String[]{hash, locator};
                            }).subscribeOn(Schedulers.boundedElastic()));
                })
                .flatMap(hl -> {
                    String hash = hl[0];
                    String locator = hl[1];
                    // Owner-scoped supersede: rejects (409) a cross-owner PUT BEFORE
                    // the new row is assembled/saved (fail-closed short-circuit).
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
                                // DOMAIN stamp (changeset 035): the bundle's brand, taken
                                // from the authenticated principal's scope — NEVER from a
                                // request param — so the metadata reads can pin to it. A
                                // SUPERADMIN publish lands in 'default' (no domain in scope),
                                // mirroring ModuleRegistryService.domainForWrite.
                                m.setDomain(domainForWrite(scope));
                                m.setCreatedAt(Instant.now());
                                return repo.save(m);
                            }));
                });
    }

    /** Fetch a file from a bundle by content-hash — the remote-fragment SYNC read. */
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
     * Read the CALLER'S OWN current card body by slug — the entry-file bytes of the
     * caller's active (non-superseded) bundle for that slug. This is the
     * read-my-card-body the user-bff proxies so the WYSIWYG editor can pre-fill for
     * Edit. Owner-scoped: only the row owned by {@code ownerUserId} is read (an
     * {@code admin} caller reads the slug's active row regardless of owner).
     *
     * <p>404 if the caller has no active bundle for the slug, or its entry file is
     * gone from storage.
     */
    public Mono<Resource> readOwnBody(String ownerUserId, String slug, boolean admin) {
        return activeRowForCaller(ownerUserId, slug, admin)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no body for slug: " + slug)))
                .flatMap(m -> {
                    String entry = (m.getEntryFile() == null || m.getEntryFile().isBlank())
                            ? "remoteEntry.json" : m.getEntryFile();
                    // storage.read returns null when the entry file is gone; wrap in
                    // Optional so Reactor doesn't silently drop the null into onComplete.
                    return Mono.fromCallable(() -> java.util.Optional.ofNullable(storage.read(m.getVersionDir(), entry)))
                            .subscribeOn(Schedulers.boundedElastic())
                            .flatMap(opt -> opt
                                    .<Mono<Resource>>map(Mono::just)
                                    .orElseGet(() -> Mono.error(
                                            new ResponseStatusException(NOT_FOUND, "no body for slug: " + slug))));
                });
    }

    /**
     * DELETE the CALLER'S OWN current bundle for a slug. Finds the caller's active
     * (non-superseded) {@code user_modules} row, removes its content-addressed
     * version from {@link BundleStorage}, and marks the row superseded (mirroring
     * {@link #supersedePrior}) so history stays queryable — the slug simply has no
     * active version afterwards. Owner-scoped: only the caller's own row is touched
     * (an {@code admin} caller may delete the slug's active row regardless of owner).
     *
     * <p>404 if the caller has no active bundle for the slug (so a delete of
     * someone-else's card surfaces as not-found to a non-admin, never as a
     * cross-tenant delete).
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

    /**
     * The active row the caller may read/delete: an admin gets the slug's active
     * row regardless of owner; a normal user gets ONLY their own active row (so a
     * non-owner sees an empty Mono -> 404, never another user's bundle).
     */
    private Mono<UserModule> activeRowForCaller(String ownerUserId, String slug, boolean admin) {
        return admin
                ? repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(slug)
                : repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(slug, ownerUserId);
    }

    /**
     * Supersede the slug's CURRENT active row on behalf of {@code ownerUserId},
     * owner-scoped and fail-closed:
     * <ul>
     *   <li>no active row for the slug — nothing to supersede (a first publish);</li>
     *   <li>active row owned by the caller (or the caller is {@code admin}) —
     *       supersede it, then the new version is inserted;</li>
     *   <li>active row owned by ANOTHER user and the caller is not admin —
     *       error 409 BEFORE any write, so a cross-owner PUT can never displace
     *       the victim's active card (their row is left untouched).</li>
     * </ul>
     * The conflict check uses the slug-only active finder and compares the row's
     * owner against the JWT subject (the same owner == subject rule read/delete
     * enforce); we do NOT rely on the owner-scoped finder alone, because a missing
     * own-row would otherwise silently fall through to a first-publish and leave a
     * rival owner's active row in place (two active rows for one slug).
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

    /** SHA-256 over the (sorted) file contents of the staging tree -> hex. */
    private static String sha256OfTree(Path dir) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (var files = Files.walk(dir)) {
                files.filter(Files::isRegularFile).sorted().forEach(p -> {
                    try {
                        md.update(dir.relativize(p).toString().getBytes());
                        md.update(Files.readAllBytes(p));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
