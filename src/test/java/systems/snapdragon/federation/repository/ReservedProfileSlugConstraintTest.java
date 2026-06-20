package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.support.TestDatabaseConfig;

/**
 * DB-LEVEL reserved-username guard slice test over H2 (PostgreSQL-compat) with the
 * REAL Liquibase changelog applied (TestDatabaseConfig → changeset 016's CHECK
 * constraint). Proves the backstop independent of the serving layer:
 * <ul>
 *   <li>a {@code profile-<reserved>} fragment insert is REJECTED by the DB
 *       ({@code ck_fed_modules_reserved_profile_slug});</li>
 *   <li>a {@code profile-<normal-username>} fragment insert SUCCEEDS;</li>
 *   <li>a reserved-named row of a NON-fragment kind is unaffected (the constraint
 *       only constrains the profile-fragment naming space).</li>
 * </ul>
 * Run via {@link DatabaseClient} raw INSERT so the assertion is the constraint
 * itself, not any application-layer filtering.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class ReservedProfileSlugConstraintTest {

    @Autowired DatabaseClient db;

    private Long insertFragment(String slug, String kind) {
        return db.sql("INSERT INTO federation_modules "
                        + "(slug, display_name, kind, remote_entry_url, owner_user_id, version, "
                        + " content_hash, visibility, enabled, circuit_state, metadata) "
                        + "VALUES (:slug, :dn, :kind, :url, :owner, '0.1.0', "
                        + " '00', 'public', true, 'closed', '{}')")
                .bind("slug", slug)
                .bind("dn", slug)
                .bind("kind", kind)
                .bind("url", "/_fragments/" + slug + "/remoteEntry.json")
                .bind("owner", slug.replace("profile-", ""))
                .filter(s -> s.returnGeneratedValues("id"))
                .map(row -> row.get("id", Long.class))
                .first()
                .block();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "profile-admin", "profile-api", "profile-login", "profile-mod",
            "profile-bff", "profile-user", "profile-games", "profile-play",
            "profile-id", "profile-www", "profile-_matrix", "profile-oauth",
            "profile-publisher", "profile-registry", "profile-actuator",
            // phpBB forum: 'forum' reserved (changeset 021 DROP+re-ADD of the 017 CHECK)
            "profile-forum",
            // Kiwix wiki: 'wiki' reserved (changeset 027 DROP+re-ADD of the CHECK)
            "profile-wiki"})
    void reservedProfileFragmentInsert_isRejectedByCheckConstraint(String reservedSlug) {
        StepVerifier.create(
                        db.sql("INSERT INTO federation_modules "
                                        + "(slug, display_name, kind, remote_entry_url, version, "
                                        + " visibility, enabled, circuit_state) "
                                        + "VALUES (:slug, :slug, 'fragment', '/x', '0.1.0', "
                                        + " 'public', true, 'closed')")
                                .bind("slug", reservedSlug)
                                .fetch().rowsUpdated())
                .expectError() // CHECK violation surfaces as an R2DBC data-integrity error
                .verify();
    }

    @Test
    void normalUsernameProfileFragment_isAccepted() {
        // 'carol' is NOT seeded by 015 (alice/bob are) and is NOT reserved.
        Long id = insertFragment("profile-carol", "fragment");
        org.assertj.core.api.Assertions.assertThat(id).isNotNull();
    }

    @Test
    void reservedNameButNonFragmentKind_isAccepted() {
        // The CHECK only constrains kind='fragment'. A reserved-named non-fragment
        // row (host/remote-shell/remote-game) is unaffected — verify a
        // 'profile-admin' SHELL row is allowed, only the FRAGMENT one is blocked.
        Long id = insertFragment("profile-admin", "remote-shell");
        org.assertj.core.api.Assertions.assertThat(id).isNotNull();
    }
}
