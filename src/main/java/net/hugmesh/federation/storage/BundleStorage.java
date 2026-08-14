package net.hugmesh.federation.storage;

import org.springframework.core.io.Resource;

import java.nio.file.Path;

/**
 * Storage strategy for federated-module bundles. Lifted from the games
 * {@code UploadStorage} interface: a pluggable, opaque-locator store with a
 * filesystem default and an S3/MinIO implementation.
 *
 * <p>Logical layout, identical across strategies:
 * <pre>
 *   &lt;root&gt; / &lt;slug&gt; / &lt;content-hash&gt; / &lt;relative file&gt;
 * </pre>
 *
 * <p>The locator returned by {@link #installFromStaging} is the protocol-prefixed
 * string {@link #read} understands ({@code file:/abs/path} for filesystem,
 * {@code s3://bucket/key} for S3). Callers treat it as opaque and persist it in
 * {@code user_modules.version_dir}. The {@code hugmesh-remote-fragment} pods
 * call {@link #read}/{@link #exists} to SYNC a bundle by content-hash and serve
 * it as static files (sync-and-serve-static).
 */
public interface BundleStorage {

    /**
     * Persist every file in {@code stagingDir} under
     * {@code <slug>/<contentHash>/<relative-path>}. Returns an opaque locator the
     * caller stores so subsequent reads find the same content. If the same
     * content-hash is already installed the staging dir is consumed and the
     * existing version is reused (content-addressed dedupe). The staging dir is
     * consumed either way — the caller must not reuse it.
     */
    String installFromStaging(String slug, String contentHash, Path stagingDir);

    /**
     * Stream {@code locator/relativePath} as a Spring {@link Resource}, or
     * {@code null} when the file isn't present (caller decides 404 vs fallback).
     */
    Resource read(String locator, String relativePath);

    /** Cheap existence probe used before serving / syncing. */
    boolean exists(String locator, String relativePath);

    /** Remove every file under {@code locator} (called when a version is superseded). */
    void deleteVersion(String locator);

    /** Implementation name for log lines ({@code filesystem} / {@code s3}). */
    String label();
}
