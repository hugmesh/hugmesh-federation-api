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
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.federation.storage.BundleStorage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
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

    public Flux<UserModule> listForSlug(String slug) {
        return repo.findBySlugOrderByCreatedAtDesc(slug);
    }

    public Mono<UserModule> byContentHash(String contentHash) {
        return repo.findByContentHash(contentHash)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no bundle: " + contentHash)));
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
     */
    public Mono<UserModule> put(String ownerUserId, String slug, String entryFile,
                                String visibility, String manifestJson, Flux<DataBuffer> body) {
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
                    return supersedePrior(slug)
                            .then(Mono.defer(() -> {
                                UserModule m = new UserModule();
                                m.setOwnerUserId(ownerUserId);
                                m.setSlug(slug);
                                m.setVersionDir(locator);
                                m.setContentHash(hash);
                                m.setManifestJson(manifestJson == null ? "{}" : manifestJson);
                                m.setVisibility(visibility == null ? "internal" : visibility);
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

    private Mono<Void> supersedePrior(String slug) {
        return repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(slug)
                .flatMap(prior -> {
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
