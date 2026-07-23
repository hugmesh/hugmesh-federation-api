package systems.hugmesh.federation.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Host-filesystem {@link BundleStorage}. Lifted from the games
 * {@code FilesystemUploadStorage}: bundle files land under
 * {@code <bundlesDir>/<slug>/<content-hash>/} and reads stream straight off disk
 * with zip-slip-safe path resolution.
 *
 * <p>Locator format: {@code file:/absolute/path/to/version-dir} (the
 * {@code file:} prefix is the discriminator the strategy router uses).
 */
public class FilesystemBundleStorage implements BundleStorage {

    private static final Logger log = LoggerFactory.getLogger(FilesystemBundleStorage.class);
    private static final String PREFIX = "file:";

    private final Path bundlesDir;

    public FilesystemBundleStorage(Path bundlesDir) {
        this.bundlesDir = bundlesDir;
    }

    @Override
    public String installFromStaging(String slug, String contentHash, Path stagingDir) {
        try {
            Path slugDir = bundlesDir.resolve(slug);
            Files.createDirectories(slugDir);
            Path versionDir = slugDir.resolve(contentHash);
            if (Files.exists(versionDir)) {
                // Same hash already installed — content-addressed dedupe: drop the
                // staging copy and reuse the existing version directory.
                deleteRecursively(stagingDir);
            } else {
                Files.move(stagingDir, versionDir, StandardCopyOption.ATOMIC_MOVE);
            }
            return PREFIX + versionDir;
        } catch (IOException ex) {
            deleteRecursively(stagingDir);
            throw new ResponseStatusException(BAD_REQUEST, "bundle install failed: " + ex.getMessage());
        }
    }

    @Override
    public Resource read(String locator, String relativePath) {
        Path base = pathFromLocator(locator);
        if (base == null) return null;
        Path target = base.resolve(relativePath).normalize();
        if (!target.startsWith(base) || !Files.isRegularFile(target)) {
            return null;
        }
        return new FileSystemResource(target);
    }

    @Override
    public boolean exists(String locator, String relativePath) {
        Path base = pathFromLocator(locator);
        if (base == null) return false;
        Path target = base.resolve(relativePath).normalize();
        return target.startsWith(base) && Files.isRegularFile(target);
    }

    @Override
    public void deleteVersion(String locator) {
        Path base = pathFromLocator(locator);
        if (base == null || !Files.exists(base)) return;
        deleteRecursively(base);
    }

    @Override
    public String label() {
        return "filesystem";
    }

    /**
     * Accepts both the prefixed locator ({@code file:/path}) AND a raw absolute
     * path (so any pre-prefix rows keep resolving). New writes always use the
     * prefixed form.
     */
    private static Path pathFromLocator(String locator) {
        if (locator == null || locator.isBlank()) return null;
        String raw = locator.startsWith(PREFIX) ? locator.substring(PREFIX.length()) : locator;
        return Path.of(raw).normalize();
    }

    private static void deleteRecursively(Path dir) {
        if (dir == null || !Files.exists(dir)) return;
        try (var stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); }
                catch (IOException ignored) { /* best effort */ }
            });
        } catch (IOException ex) {
            log.warn("[bundle-storage] failed to delete {}", dir, ex);
        }
    }
}
