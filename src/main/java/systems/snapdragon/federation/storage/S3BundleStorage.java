package systems.snapdragon.federation.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Path;

import static org.springframework.http.HttpStatus.NOT_IMPLEMENTED;

/**
 * S3 / MinIO {@link BundleStorage} — STUB.
 *
 * <p>The games {@code S3UploadStorage} (decision 020) is the production-proven
 * reference: it copies the staging tree into an S3-compatible bucket under
 * {@code <slug>/<hash>/...}, reads via {@code GetObject} into a
 * {@code ByteArrayResource}, and is wrapped in a Resilience4j circuit breaker so
 * a hung endpoint soft-fails reads. Porting it here is intentionally DEFERRED
 * (see README): it needs the {@code software.amazon.awssdk:s3} dependency + the
 * presigner wiring + the circuit-breaker config the games BFF carries.
 *
 * <p>Locator scheme (for when this is implemented): {@code s3://<bucket>/<slug>/<hash>}.
 *
 * <p>Selecting {@code app.bundles.storage=s3} today wires THIS bean and every
 * operation throws 501 so the misconfiguration is loud rather than silently
 * dropping bundles. The default {@code filesystem} strategy is fully functional.
 */
public class S3BundleStorage implements BundleStorage {

    private static final Logger log = LoggerFactory.getLogger(S3BundleStorage.class);

    private final String bucket;
    private final String endpoint;

    public S3BundleStorage(String bucket, String endpoint) {
        this.bucket = bucket;
        this.endpoint = endpoint;
        log.warn("[bundle-storage] S3 strategy selected but NOT YET IMPLEMENTED "
                + "(bucket={} endpoint={}). Port the games S3UploadStorage (decision 020) "
                + "to enable. Falling back is a config change: app.bundles.storage=filesystem.",
                bucket, endpoint);
    }

    private static ResponseStatusException notImplemented() {
        return new ResponseStatusException(NOT_IMPLEMENTED,
                "S3 bundle storage not yet implemented — use app.bundles.storage=filesystem "
                + "(port games S3UploadStorage, decision 020).");
    }

    @Override
    public String installFromStaging(String slug, String contentHash, Path stagingDir) {
        throw notImplemented();
    }

    @Override
    public Resource read(String locator, String relativePath) {
        throw notImplemented();
    }

    @Override
    public boolean exists(String locator, String relativePath) {
        throw notImplemented();
    }

    @Override
    public void deleteVersion(String locator) {
        throw notImplemented();
    }

    @Override
    public String label() {
        return "s3(stub:bucket=" + bucket + ")";
    }
}
