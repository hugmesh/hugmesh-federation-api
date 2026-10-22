package net.hugmesh.federation.repository;

import liquibase.integration.spring.SpringLiquibase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins how the module-registry seeds (022-038) and the rebrand UPDATEs (039, 041)
 * fit together, against the REAL changelog on H2 (PostgreSQL mode).
 *
 * <ul>
 *   <li>Fresh database: every seed already carries the hugmesh-* host, so each
 *       rebrand UPDATE finds nothing and records MARK_RAN. If a seed reverted to a
 *       pre-rebrand host, the matching UPDATE would EXECUTE and this goes red even
 *       though the final URL would still look right.</li>
 *   <li>Database seeded before the seeds were rebranded: the UPDATEs match the old
 *       host by shape (a ten-character brand prefix) and repoint it, while an
 *       operator override of a different shape is left alone.</li>
 * </ul>
 */
class RebrandRemoteEntryMigrationTest {

    // TestDatabaseConfig's options minus DATABASE_TO_LOWER: with lower-cased names a
    // SECOND Liquibase run on the same H2 database fails to see its own
    // databasechangelog table and tries to create it again.
    private static final String H2_OPTS =
            ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION";

    private static final String CHANGELOG = "classpath:db/changelog/db.changelog-master.xml";

    /** A stand-in for the retired brand prefix: any ten characters have its shape. */
    private static final String LEGACY_PREFIX = "http://legacybrnd-";

    private static final String HUGMESH_PREFIX = "http://hugmesh-";

    private static final String REBRAND_IDS =
            "id = '039-1-rebrand-character-forge-remote-entry' OR id LIKE '041-%'";

    private DriverManagerDataSource dataSource;
    private JdbcTemplate jdbc;

    @BeforeEach
    void freshDatabase() throws Exception {
        dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUrl("jdbc:h2:mem:rebrand_" + UUID.randomUUID().toString().replace("-", "")
                + H2_OPTS);
        dataSource.setUsername("sa");
        dataSource.setPassword("");
        jdbc = new JdbcTemplate(dataSource);
        migrate();
    }

    private void migrate() throws Exception {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(dataSource);
        lb.setChangeLog(CHANGELOG);
        lb.setResourceLoader(new DefaultResourceLoader());
        lb.afterPropertiesSet();
    }

    private Map<String, String> exectypes() {
        Map<String, String> out = new TreeMap<>();
        jdbc.queryForList("SELECT id, exectype FROM databasechangelog WHERE " + REBRAND_IDS)
                .forEach(r -> out.put((String) r.get("id"), (String) r.get("exectype")));
        return out;
    }

    private String url(String slug) {
        return jdbc.queryForObject(
                "SELECT remote_entry_url FROM federation_modules WHERE slug = ?", String.class, slug);
    }

    @Test
    void freshDatabase_seedsHugmeshHosts_soEveryRebrandUpdateMarksRan() {
        Map<String, String> types = exectypes();
        // 039-1 plus 041-1..041-10.
        assertThat(types).hasSize(11);
        assertThat(types).allSatisfy((id, type) -> assertThat(type).as(id).isEqualTo("MARK_RAN"));

        // The eleven rows 039/041 cover, plus character-studio (040, seeded after the
        // rebrand and never covered by an UPDATE).
        List<String> rebranded = jdbc.queryForList(
                "SELECT remote_entry_url FROM federation_modules WHERE remote_entry_url LIKE ?",
                String.class, HUGMESH_PREFIX + "%");
        assertThat(rebranded).hasSize(12);
    }

    @Test
    void databaseSeededBeforeTheRebrand_isRepointed_butAnOverrideIsKept() throws Exception {
        // Put every row 039/041 cover back into its pre-rebrand shape, except mastodon,
        // which an operator has overridden to a host of a different shape.
        // (character-studio was seeded after the rebrand and has no UPDATE.)
        int legacy = jdbc.update("UPDATE federation_modules SET remote_entry_url = "
                + "REPLACE(remote_entry_url, ?, ?) WHERE remote_entry_url LIKE ? "
                + "AND slug NOT IN ('mastodon', 'character-studio')",
                HUGMESH_PREFIX, LEGACY_PREFIX, HUGMESH_PREFIX + "%");
        assertThat(legacy).isEqualTo(10);
        String override = "http://custom-mastodon-ui:8080/remoteEntry.json";
        jdbc.update("UPDATE federation_modules SET remote_entry_url = ? WHERE slug = 'mastodon'",
                override);
        // ...and forget that the rebrand UPDATEs ever ran, as on a database that
        // predates them.
        jdbc.update("DELETE FROM databasechangelog WHERE " + REBRAND_IDS);

        migrate();

        assertThat(url("forum")).isEqualTo("http://hugmesh-forum-ui:8080/remoteEntry.json");
        assertThat(url("apidocs")).isEqualTo("http://hugmesh-api-docs:8080/remoteEntry.json");
        assertThat(url("character-forge"))
                .isEqualTo("http://hugmesh-character-forge-ui:8080/remoteEntry.json");
        assertThat(url("mastodon")).isEqualTo(override);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM federation_modules "
                + "WHERE remote_entry_url LIKE ?", Integer.class, LEGACY_PREFIX + "%")).isZero();

        Map<String, String> types = exectypes();
        assertThat(types).hasSize(11);
        assertThat(types).containsEntry("041-2-rebrand-mastodon-remote-entry", "MARK_RAN");
        types.remove("041-2-rebrand-mastodon-remote-entry");
        assertThat(types).allSatisfy((id, type) -> assertThat(type).as(id).isEqualTo("EXECUTED"));
    }
}
