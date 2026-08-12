package systems.hugmesh.federation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import systems.hugmesh.federation.cache.ManifestCache;
import systems.hugmesh.federation.storage.BundleStorage;
import net.hugmesh.commons.testsupport.PostgresTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full-context smoke test: the whole application boots with the {@code test}
 * profile (a real Postgres container for R2DBC + Liquibase via PostgresTestSupport,
 * Cassandra disabled, filesystem bundle storage). Proves the bean graph wires —
 * including the security filter chain, the controllers, and the graceful-degrade
 * defaults (noop manifest cache, filesystem storage) — with no other external infra
 * reachable.
 */
@SpringBootTest
@ActiveProfiles("test")
class FederationApplicationContextTest extends PostgresTestSupport {

    @Autowired ManifestCache manifestCache;
    @Autowired BundleStorage bundleStorage;

    @Test
    void contextLoads_withDegradedDefaults() {
        // Cassandra disabled -> the noop cache wins (graceful degrade).
        assertThat(manifestCache.label()).isEqualTo("noop");
        // Default storage strategy is filesystem.
        assertThat(bundleStorage.label()).isEqualTo("filesystem");
    }
}
