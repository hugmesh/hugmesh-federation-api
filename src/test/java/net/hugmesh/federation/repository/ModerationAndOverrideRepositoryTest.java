package net.hugmesh.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import net.hugmesh.federation.config.R2dbcConvertersConfig;
import net.hugmesh.federation.model.FederationOverride;
import net.hugmesh.federation.model.ModerationRequest;
import net.hugmesh.federation.support.TestDatabaseConfig;

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

        // The @DataR2dbcTest slice shares one H2 store per CLASS, so other methods'
        // rows may be present; match on the unique target this method wrote.
        List<FederationOverride> mine = overrides.findByTarget("games-dodecahedron")
                .collectList().block();
        assertThat(mine).hasSize(1);
        assertThat(mine.get(0).getAction()).isEqualTo("circuit-break");
        assertThat(mine.get(0).getScope()).isEqualTo("all");
        assertThat(mine.get(0).getTarget()).isEqualTo("games-dodecahedron");
        // cleared_at (changeset 014) round-trips: NULL on a freshly-applied row.
        assertThat(mine.get(0).getClearedAt()).isNull();
    }

    @Test
    void clearedAtColumn_applies_andActiveSetFinderFiltersByClearedAtIsNull() {
        // Two active scope rows (cleared_at NULL) + one already-cleared row.
        FederationOverride activeUser = new FederationOverride();
        activeUser.setScope("user");
        activeUser.setTarget("ownerX");
        activeUser.setAction("circuit-break");
        activeUser.setSetBy("admin-1");
        activeUser.setTs(Instant.now());
        overrides.save(activeUser).block();

        FederationOverride activeAll = new FederationOverride();
        activeAll.setScope("all");
        activeAll.setAction("unpublish");
        activeAll.setSetBy("admin-1");
        activeAll.setTs(Instant.now());
        overrides.save(activeAll).block();

        FederationOverride cleared = new FederationOverride();
        cleared.setScope("user");
        cleared.setTarget("ownerY");
        cleared.setAction("circuit-break");
        cleared.setSetBy("admin-1");
        cleared.setTs(Instant.now());
        cleared.setClearedAt(Instant.now()); // already rearmed
        overrides.save(cleared).block();

        // The read-path active-set finder returns ONLY the cleared_at IS NULL rows.
        // (The slice shares one H2 store per class; assert on the rows THIS method
        // wrote rather than the absolute count.)
        List<FederationOverride> active = overrides
                .findByScopeInAndClearedAtIsNull(List.of("all", "user", "role"))
                .collectList().block();
        assertThat(active).anyMatch(o -> "user".equals(o.getScope()) && "ownerX".equals(o.getTarget()));
        assertThat(active).anyMatch(o -> "all".equals(o.getScope()));
        // The already-cleared row (cleared_at IS NOT NULL) must be excluded.
        assertThat(active).noneMatch(o -> "ownerY".equals(o.getTarget()));

        // The clearScope target finder narrows to the specific active scope row.
        assertThat(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "ownerX")
                .collectList().block()).hasSize(1);
        // ownerY was cleared, so its target finder returns nothing.
        assertThat(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "ownerY")
                .collectList().block()).isEmpty();
        // The scope=all active finder returns at least this method's all-row.
        assertThat(overrides.findByScopeAndClearedAtIsNull("all")
                .collectList().block()).isNotEmpty();
    }
}
