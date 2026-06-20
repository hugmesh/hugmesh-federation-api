package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DB-LEVEL backstop for the owner-scoped PUT (finding A01 / CWE-639: cross-owner
 * supersede / BFLA). Slice test over H2 (PostgreSQL-compat) with the REAL Liquibase
 * changelog applied (changeset 034). Proves the active-owner uniqueness invariant
 * independent of the service layer:
 * <ul>
 *   <li>two ACTIVE rows for the SAME (slug, owner) are REJECTED by the unique
 *       index — so even a direct writer can't create a double-active for one owner;</li>
 *   <li>two ACTIVE rows for the same slug but DIFFERENT owners are ALLOWED (each
 *       owner keeps their own active card; the slug namespace is per-owner);</li>
 *   <li>a SUPERSEDED row never collides — history stays insertable (the supersede
 *       -> re-publish lifecycle the service drives still works).</li>
 * </ul>
 * Uses the real {@link UserModuleRepository} save so the assertion is the DB
 * constraint, not any application-layer filtering.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class UserModuleActiveOwnerUniqueTest {

    @Autowired UserModuleRepository repo;

    private static UserModule row(String slug, String owner, String hash) {
        UserModule m = new UserModule();
        m.setOwnerUserId(owner);
        m.setSlug(slug);
        m.setVersionDir("file:/bundles/" + slug + "/" + hash);
        m.setEntryFile("remoteEntry.json");
        m.setContentHash(hash);
        m.setManifestJson("{}");
        m.setVisibility("internal");
        m.setCreatedAt(Instant.now());
        return m;
    }

    @Test
    void twoActiveRows_sameSlugSameOwner_areRejected() {
        repo.save(row("dup-slug", "alice", "hash-a1")).block();

        // A second ACTIVE row for the same (slug, owner) violates the unique index.
        StepVerifier.create(repo.save(row("dup-slug", "alice", "hash-a2")))
                .expectError() // unique-violation surfaces as an R2DBC data-integrity error
                .verify();
    }

    @Test
    void twoActiveRows_sameSlugDifferentOwners_areAllowed() {
        UserModule alice = repo.save(row("shared", "alice", "hash-al")).block();
        UserModule bob = repo.save(row("shared", "bob", "hash-bo")).block();

        assertThat(alice).isNotNull();
        assertThat(bob).isNotNull();
        assertThat(bob.getId()).isNotEqualTo(alice.getId());
    }

    @Test
    void supersededRow_neverCollides_soRepublishWorks() {
        // alice publishes v1, supersedes it (the delete/PUT lifecycle), then publishes
        // v2 active for the same slug — the superseded v1 must NOT block v2.
        UserModule v1 = repo.save(row("evolving", "alice", "hash-v1")).block();
        assertThat(v1).isNotNull();
        v1.setSupersededAt(Instant.now());
        repo.save(v1).block();

        StepVerifier.create(repo.save(row("evolving", "alice", "hash-v2")))
                .assertNext(v2 -> assertThat(v2.getSupersededAt()).isNull())
                .verifyComplete();

        // And a second superseded history row for the same (slug, owner) is fine too.
        UserModule another = row("evolving", "alice", "hash-v0");
        another.setSupersededAt(Instant.now());
        StepVerifier.create(repo.save(another))
                .expectNextCount(1)
                .verifyComplete();
    }
}
