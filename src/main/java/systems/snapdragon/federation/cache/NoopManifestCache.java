package systems.snapdragon.federation.cache;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationManifestDto;

/**
 * Default {@link ManifestCache} when Cassandra is disabled (the common dev / CI /
 * test case): every read misses and every write is a no-op, so the manifest
 * service always renders from Postgres. Registered via
 * {@code @ConditionalOnMissingBean} so the {@link CassandraManifestCache} wins
 * whenever {@code app.manifest-cache.cassandra.enabled=true}.
 */
@Configuration
public class NoopManifestCache {

    @Bean
    @ConditionalOnMissingBean(ManifestCache.class)
    ManifestCache noopManifestCacheBean() {
        return new ManifestCache() {
            @Override public Mono<Void> put(FederationManifestDto manifest) { return Mono.empty(); }
            @Override public Mono<FederationManifestDto> get() { return Mono.empty(); }
            @Override public String label() { return "noop"; }
        };
    }
}
