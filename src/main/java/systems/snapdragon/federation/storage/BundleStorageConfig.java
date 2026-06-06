package systems.snapdragon.federation.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

/**
 * Selects a {@link BundleStorage} implementation by {@code app.bundles.storage}.
 * Defaults to filesystem so a vanilla {@code docker compose up -d} works with no
 * object store. Mirrors the games {@code UploadStorageConfig} strategy wiring.
 */
@Configuration
public class BundleStorageConfig {

    private static final Logger log = LoggerFactory.getLogger(BundleStorageConfig.class);

    @Bean
    @ConditionalOnProperty(name = "app.bundles.storage", havingValue = "filesystem", matchIfMissing = true)
    public BundleStorage filesystemBundleStorage(
            @Value("${app.bundles.dir:/var/snapdragon/federation/bundles}") String bundlesDir) {
        log.info("[bundle-storage] filesystem mode -> {}", bundlesDir);
        return new FilesystemBundleStorage(Path.of(bundlesDir));
    }

    @Bean
    @ConditionalOnProperty(name = "app.bundles.storage", havingValue = "s3")
    public BundleStorage s3BundleStorage(
            @Value("${app.bundles.s3.bucket:snapdragon-federation}") String bucket,
            @Value("${app.bundles.s3.endpoint:}") String endpoint) {
        return new S3BundleStorage(bucket, endpoint);
    }
}
