package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.support.TestDatabaseConfig;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice over H2 (PostgreSQL-compat) with the REAL Liquibase changelog
 * applied (TestDatabaseConfig). Validates the entity mapping + derived queries
 * against the production DDL, including the {@code clob}-as-String metadata
 * round-trip and the {@code timestamp -> Instant} converters. Mirrors admin-bff's
 * RouteAccessRepositoryTest.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class FederationModuleRepositoryTest {

    @Autowired FederationModuleRepository repo;

    @Test
    void seededModules_areLoadable_andOrdered() {
        // Liquibase 010-2 seeds host/login/admin/remote-fragment.
        List<FederationModule> all = repo.findAllByEnabledTrueOrderByKindAscSlugAsc()
                .collectList().block();
        assertThat(all).isNotEmpty();
        assertThat(all).extracting(FederationModule::getSlug)
                .contains("host", "login", "admin", "remote-fragment");

        FederationModule host = repo.findBySlug("host").block();
        assertThat(host).isNotNull();
        assertThat(host.getKind()).isEqualTo("host");
        assertThat(host.getCircuitState()).isEqualTo("closed");
        // metadata jsonb/clob round-trips as a String (no r2dbc JSONB codec).
        assertThat(host.getMetadata()).contains("shell");
        // timestamp -> Instant converter applied.
        assertThat(host.getCreatedAt()).isNotNull();
    }

    @Test
    void insertUpdateDelete_roundTrip() {
        FederationModule m = new FederationModule();
        m.setSlug("test-remote");
        m.setDisplayName("Test Remote");
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://test:8080/remoteEntry.json");
        m.setExposedModule("./Test");
        m.setOwnerUserId("casdoor-user-1");
        m.setVersion("1.0.0");
        m.setContentHash("deadbeef");
        m.setVisibility("internal");
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setMetadata("{\"k\":1}");

        FederationModule saved = repo.save(m).block();
        assertThat(saved.getId()).isNotNull();

        FederationModule got = repo.findBySlug("test-remote").block();
        assertThat(got.getOwnerUserId()).isEqualTo("casdoor-user-1");
        assertThat(got.getVisibility()).isEqualTo("internal");
        assertThat(got.getContentHash()).isEqualTo("deadbeef");

        got.setCircuitState("open");
        repo.save(got).block();
        assertThat(repo.findBySlug("test-remote").block().getCircuitState()).isEqualTo("open");

        // circuit-open rows are excluded from the closed-only manifest finder.
        List<FederationModule> closed = repo
                .findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed")
                .collectList().block();
        assertThat(closed).extracting(FederationModule::getSlug).doesNotContain("test-remote");

        repo.delete(got).block();
        assertThat(repo.findBySlug("test-remote").block()).isNull();
    }

    @Test
    void ownerScopedListing() {
        FederationModule m = new FederationModule();
        m.setSlug("owned-1");
        m.setDisplayName("Owned");
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://owned:8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility("public");
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setOwnerUserId("owner-x");
        repo.save(m).block();

        List<FederationModule> owned = repo.findByOwnerUserId("owner-x").collectList().block();
        assertThat(owned).hasSize(1);
        assertThat(owned.get(0).getSlug()).isEqualTo("owned-1");
    }
}
