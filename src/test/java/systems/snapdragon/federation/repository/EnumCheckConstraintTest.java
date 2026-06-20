package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.TestPropertySource;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.support.TestDatabaseConfig;

/**
 * DB-LEVEL enum/domain CHECK slice test over H2 (PostgreSQL-compat) with the REAL
 * Liquibase changelog applied (TestDatabaseConfig → changeset 018's CHECK
 * constraints). Proves the DB rejects the SAME out-of-vocabulary values the API
 * rejects with a 400 — the parity backstop. Raw {@link DatabaseClient} INSERTs so
 * the assertion is the constraint itself, not any application-layer filter.
 *
 * <p>Each table: a BAD enum value is rejected, a GOOD one is accepted.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
// This slice COMMITS accepted-enum rows (moderation status='approved', etc.) to
// prove the CHECK accepts good input. @DataR2dbcTest caches contexts by config, so
// a plain slice would SHARE TestDatabaseConfig's H2 store with the sibling
// ModerationAndOverrideRepositoryTest and leak those rows into its absolute
// assertions. This marker property gives THIS class its own context (hence its own
// fresh H2 db name) so the committed rows never escape the class.
@TestPropertySource(properties = "test.slice=enum-check-constraint")
class EnumCheckConstraintTest {

    @Autowired DatabaseClient db;

    // ---- federation_modules.kind / visibility / circuit_state ----

    @Test
    void federationModules_badKind_isRejected() {
        StepVerifier.create(insertModule("k-bad", "BOGUS", "public", "closed"))
                .expectError().verify();
    }

    @Test
    void federationModules_badVisibility_isRejected() {
        StepVerifier.create(insertModule("v-bad", "fragment", "secret", "closed"))
                .expectError().verify();
    }

    @Test
    void federationModules_badCircuitState_isRejected() {
        StepVerifier.create(insertModule("c-bad", "fragment", "public", "tripped"))
                .expectError().verify();
    }

    @Test
    void federationModules_validEnums_areAccepted() {
        StepVerifier.create(insertModule("ok-mod", "remote-shell", "internal", "open"))
                .expectNextMatches(n -> n == 1L)
                .verifyComplete();
    }

    private reactor.core.publisher.Mono<Long> insertModule(String slug, String kind,
                                                            String visibility, String circuit) {
        return db.sql("INSERT INTO federation_modules "
                        + "(slug, display_name, kind, remote_entry_url, version, "
                        + " visibility, enabled, circuit_state) "
                        + "VALUES (:slug, :slug, :kind, '/r', '0.1.0', :vis, true, :circ)")
                .bind("slug", slug).bind("kind", kind).bind("vis", visibility).bind("circ", circuit)
                .fetch().rowsUpdated();
    }

    // ---- user_modules.visibility ----

    @Test
    void userModules_badVisibility_isRejected() {
        StepVerifier.create(insertUserModule("hash-bad", "nope"))
                .expectError().verify();
    }

    @Test
    void userModules_validVisibility_isAccepted() {
        StepVerifier.create(insertUserModule("aa11", "public"))
                .expectNextMatches(n -> n == 1L)
                .verifyComplete();
    }

    private reactor.core.publisher.Mono<Long> insertUserModule(String hash, String visibility) {
        return db.sql("INSERT INTO user_modules "
                        + "(owner_user_id, slug, version_dir, content_hash, manifest_json, visibility) "
                        + "VALUES ('u1', 'my-card', 'file:/x', :hash, '{}', :vis)")
                .bind("hash", hash).bind("vis", visibility)
                .fetch().rowsUpdated();
    }

    // ---- moderation_requests.kind / status ----

    @Test
    void moderationRequests_badKind_isRejected() {
        StepVerifier.create(insertModeration("banhammer", "recommended"))
                .expectError().verify();
    }

    @Test
    void moderationRequests_badStatus_isRejected() {
        StepVerifier.create(insertModeration("instance-block", "maybe"))
                .expectError().verify();
    }

    @Test
    void moderationRequests_validEnums_areAccepted() {
        StepVerifier.create(insertModeration("user-removal", "approved"))
                .expectNextMatches(n -> n == 1L)
                .verifyComplete();
    }

    private reactor.core.publisher.Mono<Long> insertModeration(String kind, String status) {
        return db.sql("INSERT INTO moderation_requests (requester, kind, target, status) "
                        + "VALUES ('mod1', :kind, 'evil.example', :status)")
                .bind("kind", kind).bind("status", status)
                .fetch().rowsUpdated();
    }

    // ---- federation_override.scope / action ----

    @Test
    void federationOverride_badScope_isRejected() {
        StepVerifier.create(insertOverride("galaxy", "circuit-break"))
                .expectError().verify();
    }

    @Test
    void federationOverride_badAction_isRejected() {
        StepVerifier.create(insertOverride("user", "nuke"))
                .expectError().verify();
    }

    @Test
    void federationOverride_validEnums_areAccepted() {
        StepVerifier.create(insertOverride("all", "unpublish"))
                .expectNextMatches(n -> n == 1L)
                .verifyComplete();
    }

    private reactor.core.publisher.Mono<Long> insertOverride(String scope, String action) {
        return db.sql("INSERT INTO federation_override (scope, target, action, set_by) "
                        + "VALUES (:scope, 't', :action, 'admin1')")
                .bind("scope", scope).bind("action", action)
                .fetch().rowsUpdated();
    }
}
