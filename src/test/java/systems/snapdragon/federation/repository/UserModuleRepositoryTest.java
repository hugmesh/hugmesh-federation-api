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

    @Test
    void ownerScopedActiveFinder_returnsCallersOwnRowOnly() {
        // alice + bob both publish a slug; the owner-scoped finder (the read/delete
        // anchor) returns ONLY the caller's own active row, never the other user's.
        UserModule alice = um("shared-slug", "hash-alice");
        alice.setOwnerUserId("alice");
        repo.save(alice).block();
        UserModule bob = um("shared-slug", "hash-bob");
        bob.setOwnerUserId("bob");
        repo.save(bob).block();

        UserModule aliceActive = repo
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc("shared-slug", "alice")
                .block();
        assertThat(aliceActive).isNotNull();
        assertThat(aliceActive.getContentHash()).isEqualTo("hash-alice");

        // A non-owner of any row for the slug gets nothing (-> 404 in the service).
        UserModule strangerActive = repo
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc("shared-slug", "carol")
                .block();
        assertThat(strangerActive).isNull();
    }

    @Test
    void entryFile_roundTrips_andDefaultsForLegacyRow() {
        // A writer that sets entry_file round-trips it ...
        UserModule withEntry = um("with-entry", "hash-entry");
        withEntry.setEntryFile("card.html");
        repo.save(withEntry).block();
        UserModule got = repo.findByContentHash("hash-entry").block();
        assertThat(got).isNotNull();
        assertThat(got.getEntryFile()).isEqualTo("card.html");

        // ... and a legacy writer that omits it inserts the column default.
        UserModule legacy = um("legacy", "hash-legacy");
        repo.save(legacy).block();
        UserModule legacyGot = repo.findByContentHash("hash-legacy").block();
        assertThat(legacyGot).isNotNull();
        assertThat(legacyGot.getEntryFile()).isEqualTo("remoteEntry.json");
    }
}
