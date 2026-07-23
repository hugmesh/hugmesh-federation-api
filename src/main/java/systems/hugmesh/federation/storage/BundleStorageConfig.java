package systems.hugmesh.federation.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;

import java.net.URI;
import java.nio.file.Path;

/**
 * Selects a {@link BundleStorage} implementation by {@code app.bundles.storage}.
 * Defaults to filesystem so a vanilla {@code docker compose up -d} works with no
 * object store. Mirrors the games {@code UploadStorageConfig} strategy wiring.
 *
 * <p>When {@code app.bundles.storage=s3}: credentials are resolved from the standard
 * AWS credential chain (env vars {@code AWS_ACCESS_KEY_ID}/{@code AWS_SECRET_ACCESS_KEY},
 * {@code ~/.aws/credentials}, or instance-metadata on EC2/ECS). The optional
 * {@code app.bundles.s3.endpoint} overrides the S3 endpoint for MinIO in dev/CI.
 */
@Configuration
public class BundleStorageConfig {

    private static final Logger log = LoggerFactory.getLogger(BundleStorageConfig.class);

    @Bean
    @ConditionalOnProperty(name = "app.bundles.storage", havingValue = "filesystem", matchIfMissing = true)
    public BundleStorage filesystemBundleStorage(
            @Value("${app.bundles.dir:/var/hugmesh/federation/bundles}") String bundlesDir) {
        log.info("[bundle-storage] filesystem mode -> {}", bundlesDir);
        return new FilesystemBundleStorage(Path.of(bundlesDir));
    }

    @Bean
    @ConditionalOnProperty(name = "app.bundles.storage", havingValue = "s3")
    public BundleStorage s3BundleStorage(
            @Value("${app.bundles.s3.bucket:snapdragon-federation}") String bucket,
            @Value("${app.bundles.s3.endpoint:}") String endpoint,
            @Value("${app.bundles.s3.region:us-east-1}") String region) {
        S3ClientBuilder builder = S3Client.builder().region(Region.of(region));
        if (!endpoint.isBlank()) {
            // Path-style addressing is required for MinIO (it doesn't support virtual-hosted-style).
            builder.endpointOverride(URI.create(endpoint)).forcePathStyle(true);
        }
        return new S3BundleStorage(builder.build(), bucket);
    }
}
