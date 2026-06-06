package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for user_modules over H2 (PG-compat) + the real Liquibase
 * changelog. Validates the content-hash lookup (the remote-fragment sync key),
 * the clob manifest_json round-trip, and the active/superseded finder.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class UserModuleRepositoryTest {

    @Autowired UserModuleRepository repo;

    private static UserModule um(String slug, String hash) {
        UserModule m = new UserModule();
        m.setOwnerUserId("owner-1");
        m.setSlug(slug);
        m.setVersionDir("file:/var/snapdragon/federation/bundles/" + slug + "/" + hash);
        m.setContentHash(hash);
        m.setManifestJson("{\"entry\":\"remoteEntry.json\"}");
        m.setVisibility("internal");
        m.setCreatedAt(Instant.now());
        return m;
    }

    @Test
    void byContentHash_andManifestRoundTrip() {
        repo.save(um("my-remote", "hash-aaa")).block();
        UserModule got = repo.findByContentHash("hash-aaa").block();
        assertThat(got).isNotNull();
        assertThat(got.getSlug()).isEqualTo("my-remote");
        assertThat(got.getManifestJson()).contains("remoteEntry.json");
        assertThat(got.getVersionDir()).startsWith("file:");
    }

    @Test
    void activeFinder_ignoresSuperseded() {
        UserModule v1 = repo.save(um("evolving", "hash-v1")).block();
        v1.setSupersededAt(Instant.now());
        repo.save(v1).block();
        repo.save(um("evolving", "hash-v2")).block();

        UserModule active = repo
                .findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc("evolving").block();
        assertThat(active).isNotNull();
        assertThat(active.getContentHash()).isEqualTo("hash-v2");
    }
}
