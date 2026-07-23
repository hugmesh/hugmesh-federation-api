package systems.hugmesh.federation.storage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link S3BundleStorage} via the package-private {@link S3Ops} seam
 * (no Mockito-vs-S3Client overload ambiguity). Delineated per the test standard:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — installFromStaging calls put() for every file under
 *       the correct key prefix, returns the locator, cleans the staging dir; read
 *       returns a ByteArrayResource; exists delegates to headExists; deleteVersion
 *       lists + bulk-deletes.</li>
 *   <li><b>CROSS-USER (ISOLATION DENY)</b> — a locator for a different bucket returns
 *       null/false and never calls S3; a {@code file://} locator is a clean miss;
 *       a null return from {@code getOrNull} (NoSuchKey) propagates as null/false.</li>
 * </ul>
 */
class S3BundleStorageTest {

    private static final String BUCKET = "test-bucket";

    private S3Ops ops;
    private S3BundleStorage storage;

    @BeforeEach
    void setUp() {
        ops = mock(S3Ops.class);
        storage = new S3BundleStorage(ops, BUCKET);
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void installFromStaging_putsAllFiles_returnsLocator_cleansStaging(@TempDir Path tmpDir)
                throws IOException {
            Path stagingDir = tmpDir.resolve("stage");
            Files.createDirectories(stagingDir.resolve("sub"));
            Files.writeString(stagingDir.resolve("remoteEntry.json"), "{\"key\":1}");
            Files.writeString(stagingDir.resolve("sub/chunk.js"), "console.log(1)");

            String locator = storage.installFromStaging("my-card", "abc123", stagingDir);

            assertThat(locator).isEqualTo("s3://test-bucket/my-card/abc123");
            verify(ops).put(BUCKET, "my-card/abc123/remoteEntry.json", stagingDir.resolve("remoteEntry.json"));
            verify(ops).put(BUCKET, "my-card/abc123/sub/chunk.js", stagingDir.resolve("sub/chunk.js"));
            // Staging dir cleaned up.
            assertThat(stagingDir).doesNotExist();
        }

        @Test
        void installFromStaging_cleansStaging_evenWhenPutFails(@TempDir Path tmpDir)
                throws IOException {
            Path stagingDir = tmpDir.resolve("stage");
            Files.createDirectories(stagingDir);
            Files.writeString(stagingDir.resolve("remoteEntry.json"), "{}");
            when(ops.getOrNull(any(), any())).thenReturn(null); // no-op, not called on put
            // put() throws a runtime exception (e.g. S3 network error)
            org.mockito.Mockito.doThrow(new RuntimeException("network error"))
                    .when(ops).put(any(), any(), any(Path.class));

            assertThatThrownBy(() -> storage.installFromStaging("card", "hash1", stagingDir))
                    .hasMessageContaining("S3 putObject failed");
            // Staging dir cleaned up even on failure.
            assertThat(stagingDir).doesNotExist();
        }

        @Test
        void read_returnsResource_whenOpsReturnsBytes() {
            byte[] content = "hello".getBytes();
            when(ops.getOrNull(BUCKET, "my-card/abc123/remoteEntry.json")).thenReturn(content);

            Resource result = storage.read("s3://test-bucket/my-card/abc123", "remoteEntry.json");

            assertThat(result).isNotNull();
            assertThat(result.getDescription()).contains("my-card/abc123/remoteEntry.json");
            verify(ops).getOrNull(BUCKET, "my-card/abc123/remoteEntry.json");
        }

        @Test
        void exists_returnsTrue_whenHeadSucceeds() {
            when(ops.headExists(BUCKET, "my-card/abc123/remoteEntry.json")).thenReturn(true);

            assertThat(storage.exists("s3://test-bucket/my-card/abc123", "remoteEntry.json")).isTrue();
            verify(ops).headExists(BUCKET, "my-card/abc123/remoteEntry.json");
        }

        @Test
        void deleteVersion_listsAndBulkDeletes() {
            when(ops.listKeys(BUCKET, "my-card/abc123/")).thenReturn(
                    List.of("my-card/abc123/remoteEntry.json", "my-card/abc123/sub/chunk.js"));

            storage.deleteVersion("s3://test-bucket/my-card/abc123");

            verify(ops).listKeys(BUCKET, "my-card/abc123/");
            verify(ops).bulkDelete(BUCKET,
                    List.of("my-card/abc123/remoteEntry.json", "my-card/abc123/sub/chunk.js"));
        }

        @Test
        void deleteVersion_emptyListing_skipsDelete() {
            when(ops.listKeys(any(), any())).thenReturn(List.of());

            storage.deleteVersion("s3://test-bucket/my-card/abc123");

            verify(ops, never()).bulkDelete(any(), any());
        }

        @Test
        void label_returnsS3() {
            assertThat(storage.label()).isEqualTo("s3");
        }

        @Test
        void read_trailingSlashRelPath_normalised() {
            when(ops.getOrNull(BUCKET, "my-card/abc123/index.js")).thenReturn("x".getBytes());

            // A leading slash on the relative path must be stripped.
            storage.read("s3://test-bucket/my-card/abc123", "/index.js");

            verify(ops).getOrNull(BUCKET, "my-card/abc123/index.js");
        }
    }

    // ── CROSS-USER (ISOLATION DENY) ────────────────────────────────────────────────
    @Nested
    class CrossUserIsolation {

        @Test
        void read_filesystemLocator_returnsNull_noOpsCall() {
            Resource result = storage.read("file:/var/bundles/my-card/abc123", "remoteEntry.json");
            assertThat(result).isNull();
            verify(ops, never()).getOrNull(any(), any());
        }

        @Test
        void read_wrongBucket_returnsNull_noOpsCall() {
            Resource result = storage.read("s3://other-bucket/my-card/abc123", "remoteEntry.json");
            assertThat(result).isNull();
            verify(ops, never()).getOrNull(any(), any());
        }

        @Test
        void read_opsReturnsNull_propagatesAsNull() {
            when(ops.getOrNull(BUCKET, "my-card/abc123/missing.json")).thenReturn(null);

            Resource result = storage.read("s3://test-bucket/my-card/abc123", "missing.json");
            assertThat(result).isNull();
        }

        @Test
        void exists_noSuchKey_opsReturnsFalse() {
            when(ops.headExists(BUCKET, "my-card/abc123/missing.json")).thenReturn(false);

            assertThat(storage.exists("s3://test-bucket/my-card/abc123", "missing.json")).isFalse();
        }

        @Test
        void exists_filesystemLocator_returnsFalse_noOpsCall() {
            assertThat(storage.exists("file:/var/bundles/my-card/abc123", "remoteEntry.json")).isFalse();
            verify(ops, never()).headExists(any(), any());
        }

        @Test
        void exists_wrongBucket_returnsFalse_noOpsCall() {
            assertThat(storage.exists("s3://other-bucket/my-card/abc123", "remoteEntry.json")).isFalse();
            verify(ops, never()).headExists(any(), any());
        }

        @Test
        void deleteVersion_filesystemLocator_isNoOp() {
            storage.deleteVersion("file:/var/bundles/my-card/abc123");
            verify(ops, never()).listKeys(any(), any());
        }

        @Test
        void deleteVersion_wrongBucket_isNoOp() {
            storage.deleteVersion("s3://other-bucket/my-card/abc123");
            verify(ops, never()).listKeys(any(), any());
        }

        @Test
        void deleteVersion_nullLocator_isNoOp() {
            storage.deleteVersion(null);
            verify(ops, never()).listKeys(any(), any());
        }
    }
}
