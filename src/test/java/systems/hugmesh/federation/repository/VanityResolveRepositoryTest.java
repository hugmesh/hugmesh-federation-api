package systems.hugmesh.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;
import systems.hugmesh.federation.config.R2dbcConvertersConfig;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.model.FederationOverride;
import systems.hugmesh.federation.service.VanityService;
import systems.hugmesh.federation.support.TestDatabaseConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * VANITY-RESOLVE slice test over H2 (PostgreSQL-compat) with the REAL Liquibase
 * changelog applied (TestDatabaseConfig). Exercises the actual
 * {@code findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState} derived
 * query against the production DDL + the 015 seed
 * ({@code profile-alice}=public, {@code profile-bob}=internal), proving:
 * <ul>
 *   <li>a PUBLIC profile fragment resolves;</li>
 *   <li>an INTERNAL one does NOT (the public-visibility predicate excludes it);</li>
 *   <li>a non-existent username does NOT;</li>
 *   <li>the derived-query SQL compiles + runs on the real schema (the point of the
 *       H2-PG slice — same indexed DDL as production Postgres).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class VanityResolveRepositoryTest {

    @Autowired FederationModuleRepository repo;
    @Autowired FederationOverrideRepository overrides;

    // The production resolve-predicate values (kind/visibility/circuit_state) the
    // VanityService passes into the finder; inlined here (different package, the
    // service constants are package-private to its own service package).
    private static final String FRAGMENT = "fragment";
    private static final String PUBLIC = "public";
    private static final String CLOSED = "closed";

    @Test
    void resolvesSeededPublicProfileFragment() {
        StepVerifier.create(repo.findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                        VanityService.profileSlug("alice"), FRAGMENT, PUBLIC, CLOSED))
                .assertNext(m -> {
                    assertThat(m.getSlug()).isEqualTo("profile-alice");
                    assertThat(m.getKind()).isEqualTo("fragment");
                    assertThat(m.getVisibility()).isEqualTo("public");
                    assertThat(m.getOwnerUserId()).isEqualTo("alice");
                    assertThat(m.getContentHash()).isNotBlank();
                })
                .verifyComplete();
    }

    @Test
    void internalProfileFragment_isNotResolvableAsPublic() {
        // profile-bob is seeded visibility='internal' -> the public predicate
        // excludes it. The vanity read path therefore 404s for bob.
        StepVerifier.create(repo.findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                        VanityService.profileSlug("bob"), FRAGMENT, PUBLIC, CLOSED))
                .verifyComplete(); // empty

        // Sanity: bob's row DOES exist (just internal), proving the filter — not a
        // missing row — is what excludes it.
        FederationModule bob = repo.findBySlug("profile-bob").block();
        assertThat(bob).isNotNull();
        assertThat(bob.getVisibility()).isEqualTo("internal");
    }

    @Test
    void nonExistentUsername_resolvesEmpty() {
        StepVerifier.create(repo.findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                        VanityService.profileSlug("nobody"), FRAGMENT, PUBLIC, CLOSED))
                .verifyComplete(); // empty -> 404
    }

    @Test
    void endToEnd_serviceResolvesPublic_and404sInternal_overRealSchema() {
        // Real override repo too: no active scope=user ban is seeded, so the
        // owner-ban gate passes through and alice resolves over the real schema.
        VanityService svc = new VanityService(repo, overrides);

        StepVerifier.create(svc.resolve("alice"))
                .assertNext(dto -> {
                    assertThat(dto.username()).isEqualTo("alice");
                    assertThat(dto.slug()).isEqualTo("profile-alice");
                    assertThat(dto.visibility()).isEqualTo("public");
                    // content-addressed static path the host loads from.
                    assertThat(dto.fragmentPath()).startsWith("/_fragments/profile-alice/");
                })
                .verifyComplete();

        // internal + non-existent both resolve empty (controller -> 404).
        StepVerifier.create(svc.resolve("bob")).verifyComplete();
        StepVerifier.create(svc.resolve("nobody")).verifyComplete();
    }

    @Test
    void bannedOwner_404s_evenForSeededPublicFragment_overRealSchema() {
        // Apply an ACTIVE scope=user override against alice's owner_user_id via the
        // real override repo, then prove the seeded PUBLIC profile-alice fragment
        // no longer resolves (it would without the ban). Source-tagged so it could
        // be cleared by its source later.
        FederationOverride ban = new FederationOverride();
        ban.setScope("user");
        ban.setTarget("alice");
        ban.setAction("unpublish");
        ban.setSetBy("test");
        ban.setReason("access_suspension:slice");
        ban.setTs(java.time.Instant.now());
        overrides.save(ban).block();

        VanityService svc = new VanityService(repo, overrides);

        // Banned -> empty (404) despite the public+enabled+closed seed row.
        StepVerifier.create(svc.resolve("alice")).verifyComplete();

        // Clearing the row (rearm) lets alice resolve again — proves the gate is
        // driven by the ACTIVE (cleared_at IS NULL) row, not a permanent change.
        ban.setClearedAt(java.time.Instant.now());
        overrides.save(ban).block();
        StepVerifier.create(svc.resolve("alice"))
                .assertNext(dto -> assertThat(dto.slug()).isEqualTo("profile-alice"))
                .verifyComplete();
    }
}
