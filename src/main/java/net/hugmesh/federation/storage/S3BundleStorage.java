package net.hugmesh.federation.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * S3-compatible {@link BundleStorage}. Works against AWS S3 in prod and MinIO in
 * dev / CI ({@code compose.yml} ships a {@code minio} container the
 * {@code app.bundles.s3.endpoint} property points at).
 *
 * <p>Bundle files land under {@code s3://<bucket>/<slug>/<contentHash>/} keyed by
 * their relative path inside the staging dir.
 *
 * <p>Locator format: {@code s3://<bucket>/<slug>/<contentHash>}.
 *
 * <p>The synchronous S3 client is used deliberately: the async SDK pulls in Netty
 * NIO, which conflicts with Reactor Netty already on the classpath. Call sites wrap
 * calls in {@code Mono.fromCallable(...).subscribeOn(boundedElastic())}.
 * Ported from the games {@code S3UploadStorage} (decision 020).
 *
 * <p>All S3 interactions are routed through {@link S3Ops} (a thin facade with no
 * overloads) so the unit tests can mock cleanly without hitting the overload
 * ambiguity in {@code S3Client}'s generated interface.
 */
public class S3BundleStorage implements BundleStorage {

    private static final Logger log = LoggerFactory.getLogger(S3BundleStorage.class);
    private static final String PREFIX = "s3://";

    private final S3Ops ops;
    private final String bucket;

    public S3BundleStorage(S3Client s3, String bucket) {
        this(new S3ClientOps(s3), bucket);
        log.info("[bundle-storage] S3 mode -> bucket={}", bucket);
    }

    /** Package-private constructor for tests: inject any {@link S3Ops} implementation. */
    S3BundleStorage(S3Ops ops, String bucket) {
        this.ops = ops;
        this.bucket = bucket;
    }

    @Override
    public String installFromStaging(String slug, String contentHash, Path stagingDir) {
        String keyPrefix = slug + "/" + contentHash;
        try (Stream<Path> walk = Files.walk(stagingDir)) {
            walk.filter(Files::isRegularFile).forEach(p -> {
                String rel = stagingDir.relativize(p).toString().replace('\\', '/');
                String key = keyPrefix + "/" + rel;
                try {
                    ops.put(bucket, key, p);
                } catch (Exception ex) {
                    throw new ResponseStatusException(BAD_REQUEST,
                            "S3 putObject failed for " + key + ": " + ex.getMessage());
                }
            });
        } catch (IOException ex) {
            throw new ResponseStatusException(BAD_REQUEST,
                    "S3 install walk failed: " + ex.getMessage());
        } finally {
            deleteRecursively(stagingDir);
        }
        return PREFIX + bucket + "/" + keyPrefix;
    }

    @Override
    public Resource read(String locator, String relativePath) {
        String key = keyFromLocator(locator, relativePath);
        if (key == null) return null;
        try {
            byte[] raw = ops.getOrNull(bucket, key);
            if (raw == null) return null;
            return new ByteArrayResource(raw, key);
        } catch (Exception ex) {
            log.warn("[bundle-storage:s3] read failed for {}: {}", key, ex.getMessage());
            return null;
        }
    }

    @Override
    public boolean exists(String locator, String relativePath) {
        String key = keyFromLocator(locator, relativePath);
        if (key == null) return false;
        try {
            return ops.headExists(bucket, key);
        } catch (Exception ex) {
            log.warn("[bundle-storage:s3] head failed for {}: {}", key, ex.getMessage());
            return false;
        }
    }

    @Override
    public void deleteVersion(String locator) {
        String prefix = keyPrefixFromLocator(locator);
        if (prefix == null) return;
        try {
            List<String> keys = ops.listKeys(bucket, prefix + "/");
            if (keys.isEmpty()) return;
            ops.bulkDelete(bucket, keys);
        } catch (Exception ex) {
            log.warn("[bundle-storage:s3] deleteVersion failed for {}: {}", prefix, ex.getMessage());
        }
    }

    @Override
    public String label() {
        return "s3";
    }

    private String keyFromLocator(String locator, String relativePath) {
        String prefix = keyPrefixFromLocator(locator);
        if (prefix == null) return null;
        String rel = relativePath == null ? "" : relativePath;
        if (rel.startsWith("/")) rel = rel.substring(1);
        return prefix + "/" + rel;
    }

    private String keyPrefixFromLocator(String locator) {
        if (locator == null || !locator.startsWith(PREFIX)) return null;
        String stripped = locator.substring(PREFIX.length());
        int slash = stripped.indexOf('/');
        if (slash < 0) return null;
        String locBucket = stripped.substring(0, slash);
        if (!locBucket.equals(bucket)) {
            log.warn("[bundle-storage:s3] locator bucket {} != configured bucket {}; cross-stack read?",
                    locBucket, bucket);
            return null;
        }
        return stripped.substring(slash + 1);
    }

    private static void deleteRecursively(Path dir) {
        if (dir == null || !Files.exists(dir)) return;
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    log.debug("[bundle-storage:s3] failed to delete temp path {} during recursive cleanup: {}",
                            p, e.toString());
                }
            });
        } catch (IOException e) {
            log.debug("[bundle-storage:s3] failed to walk temp dir {} during recursive cleanup: {}", dir, e.toString());
        }
    }
}
