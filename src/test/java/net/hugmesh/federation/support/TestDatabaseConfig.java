package net.hugmesh.federation.support;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;
import liquibase.integration.spring.SpringLiquibase;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared slice-test database wiring, copied from admin-bff's
 * {@code TestDatabaseConfig}: a single H2 in-mem DB that Liquibase applies the
 * REAL production changelog over (via a JDBC datasource — Liquibase has no R2DBC
 * runner) AND that the runtime R2DBC repositories access reactively. The JDBC URL
 * {@code jdbc:h2:mem:<name>} and the R2DBC URL {@code r2dbc:h2:mem:///<name>}
 * resolve to the SAME H2 mem store, so the repositories run against the real
 * Liquibase-applied schema.
 *
 * <p>H2 runs in PostgreSQL-compat mode. {@code NON_KEYWORDS} neutralises the
 * reserved column names this schema uses ({@code action}, {@code target},
 * {@code value}, {@code kind} are not reserved, but {@code action} is) so the same
 * Liquibase DDL applies here and on real Postgres. The {@code ${json.type}}
 * changelog property resolves to {@code clob} on H2 (reads back as String over
 * R2DBC) and {@code jsonb} on Postgres.
 *
 * <p>Each test class gets a UNIQUE db name so classes don't share rows.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestDatabaseConfig {

    private static final AtomicInteger DB_SEQ = new AtomicInteger();

    private final String dbName = "federation_test_" + DB_SEQ.incrementAndGet();

    // CASE_INSENSITIVE_IDENTIFIERS=TRUE: under H2 (2.3.x on the Boot-4 test classpath)
    // Spring Data R2DBC's generated SQL references columns upper-cased and quoted (e.g.
    // "federation_modules"."ID" / "SLUG"), which no longer match the lower-cased physical
    // columns that DATABASE_TO_LOWER=TRUE produces from the Liquibase DDL. Enabling
    // case-insensitive identifier resolution makes the generated R2DBC SQL resolve
    // against the lower-cased schema (the behaviour the suite relied on before the bump).
    private static final String H2_OPTS =
            ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION"
            + ";DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE";

    /** The r2dbc-h2 driver sends no username by default; pin sa/empty on both
     *  handles so they share the store (admin-bff lesson). */
    private static final String R2DBC_OPTS = H2_OPTS + ";USER=sa;PASSWORD=";

    @Bean
    public DataSource liquibaseDataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.h2.Driver");
        ds.setUrl("jdbc:h2:mem:" + dbName + H2_OPTS);
        ds.setUsername("sa");
        ds.setPassword("");
        return ds;
    }

    /** Apply the production changelog over the shared H2 before the repositories run. */
    @Bean
    public SpringLiquibase liquibase(DataSource liquibaseDataSource) {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(liquibaseDataSource);
        lb.setChangeLog("classpath:db/changelog/db.changelog-master.xml");
        return lb;
    }

    @Bean
    public ConnectionFactory connectionFactory() {
        return ConnectionFactories.get("r2dbc:h2:mem:///" + dbName + R2DBC_OPTS);
    }
}
