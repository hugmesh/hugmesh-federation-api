package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for moderation_requests + federation_override over H2 (PG-compat) +
 * the real Liquibase changelog. Confirms the 012/013 DDL applies and the reserved
 * column names ({@code action}, {@code target}, {@code status}) round-trip (the
 * NON_KEYWORDS list in TestDatabaseConfig neutralises H2 reserved words so the
 * same DDL works here and on Postgres).
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class ModerationAndOverrideRepositoryTest {

    @Autowired ModerationRequestRepository moderation;
    @Autowired FederationOverrideRepository overrides;

    @Test
    void moderationRequest_statusFilter() {
        ModerationRequest r = new ModerationRequest();
        r.setRequester("mod-1");
        r.setKind("instance-block");
        r.setTarget("evil.example");
        r.setReason("spam");
        r.setStatus("recommended");
        r.setTs(Instant.now());
        moderation.save(r).block();

        List<ModerationRequest> recommended = moderation
                .findByStatusOrderByTsDesc("recommended").collectList().block();
        assertThat(recommended).hasSize(1);
        assertThat(recommended.get(0).getKind()).isEqualTo("instance-block");
        assertThat(recommended.get(0).getTarget()).isEqualTo("evil.example");

        assertThat(moderation.findByStatusOrderByTsDesc("approved").collectList().block()).isEmpty();
    }

    @Test
    void federationOverride_actionAndScopeRoundTrip() {
        FederationOverride o = new FederationOverride();
        o.setScope("all");
        o.setTarget("games-dodecahedron");
        o.setAction("circuit-break");
        o.setSetBy("admin-1");
        o.setTs(Instant.now());
        overrides.save(o).block();

        List<FederationOverride> all = overrides.findAllByOrderByTsDesc().collectList().block();
        assertThat(all).hasSize(1);
        assertThat(all.get(0).getAction()).isEqualTo("circuit-break");
        assertThat(all.get(0).getScope()).isEqualTo("all");
        assertThat(all.get(0).getTarget()).isEqualTo("games-dodecahedron");
    }
}
