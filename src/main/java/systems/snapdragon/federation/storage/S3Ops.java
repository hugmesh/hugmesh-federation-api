package systems.snapdragon.federation.storage;

import java.nio.file.Path;
import java.util.List;

/**
 * Thin façade over the S3 operations used by {@link S3BundleStorage}.
 *
 * <p>AWS SDK v2's {@code S3Client} interface has dual overloads (direct-request AND
 * {@code Consumer<Builder>}) for every operation. Those overloads cause compile-time
 * ambiguity when mocking via Mockito. This interface has exactly one method per
 * operation — no overloads — so tests can mock it cleanly.
 *
 * <p>The production implementation ({@link S3ClientOps}) wraps an {@code S3Client}.
 * {@link S3BundleStorage} depends only on {@code S3Ops}, not on the full client.
 */
interface S3Ops {
    void put(String bucket, String key, Path file);
    /** Returns the raw bytes, or {@code null} when the key doesn't exist. */
    byte[] getOrNull(String bucket, String key);
    /** Returns {@code false} when the key doesn't exist. */
    boolean headExists(String bucket, String key);
    List<String> listKeys(String bucket, String prefix);
    void bulkDelete(String bucket, List<String> keys);
}
