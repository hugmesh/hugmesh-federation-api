package systems.snapdragon.federation.cache;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The per-brand cache key {@link CassandraManifestCache#key}: every brand's
 * manifest is cached under its OWN Cassandra partition key, so a brand-B
 * poller can never be served brand-A's cached body (see {@link ManifestCache}'s
 * per-brand-cache-key contract).
 */
class CassandraManifestCacheKeyTest {

    @Test
    void distinctDomains_produceDistinctKeys() {
        assertThat(CassandraManifestCache.key("default")).isNotEqualTo(CassandraManifestCache.key("brandx"));
        assertThat(CassandraManifestCache.key("brandx")).isNotEqualTo(CassandraManifestCache.key("brandy"));
    }

    @Test
    void sameDomain_alwaysProducesTheSameKey() {
        assertThat(CassandraManifestCache.key("brandx")).isEqualTo(CassandraManifestCache.key("brandx"));
    }

    @Test
    void key_isPrefixed_soItCanNeverCollideWithAnUnrelatedRowShape() {
        assertThat(CassandraManifestCache.key("default")).isEqualTo("manifest:default");
        assertThat(CassandraManifestCache.key("brandx")).isEqualTo("manifest:brandx");
    }

    @Test
    void nullOrBlankDomain_fallsBackToDefault() {
        assertThat(CassandraManifestCache.key(null)).isEqualTo("manifest:default");
        assertThat(CassandraManifestCache.key("")).isEqualTo("manifest:default");
        assertThat(CassandraManifestCache.key("   ")).isEqualTo("manifest:default");
    }
}
