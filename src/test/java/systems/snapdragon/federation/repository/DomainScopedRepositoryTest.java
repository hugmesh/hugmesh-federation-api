package systems.snapdragon.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.config.R2dbcConvertersConfig;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real-schema (H2 PostgreSQL-compat, REAL Liquibase changelog incl. 026) coverage
 * of the DOMAIN-pinned finders — the QUERY-layer isolation boundary. Delineated:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — a domain-pinned finder returns only that domain's
 *       rows over the real DDL (+ the 026 default for seeded/legacy rows).</li>
 *   <li><b>CROSS-USER</b> — a brand-X finder NEVER returns a brand-Y row (the DB
 *       predicate is the isolation boundary); a slug that exists in brand Y returns
 *       EMPTY when queried as brand X.</li>
 *   <li><b>CONCURRENT</b> — N interleaved writes across two brands, then each brand's
 *       finder returns exactly its own rows (no cross-domain leakage under
 *       contention).</li>
 * </ul>
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
// Spring caches a @DataR2dbcTest context by its configuration; the other repository
// slice classes share ONE cached context (hence one H2 store) and assert on
// per-method unique markers rather than absolute counts. This class writes rows that
// WOULD collide with those classes' absolute-count assertions (e.g. a status=
// 'recommended' moderation row vs ModerationAndOverrideRepositoryTest's hasSize(1)),
// so a distinguishing property forces its OWN cached context + OWN H2 store —
// keeping the cross-class isolation the shared-store tests rely on intact.
@TestPropertySource(properties = "test.context = domain-scoped-repo")
class DomainScopedRepositoryTest {

    @Autowired FederationModuleRepository modules;
    @Autowired FederationOverrideRepository overrides;
    @Autowired ModerationRequestRepository moderation;

    private static FederationModule module(String slug, String domain) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility("public");
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setDomain(domain);
        return m;
    }

    // USER-SITUATIONAL: the 010-2 seed + 022/023/024/025 registrations default to
    // 'default' (026 NOT-NULL default), so a default-domain finder sees them.
    @Test
    void seededRows_defaultToDefaultDomain() {
        FederationModule host = modules.findBySlugAndDomain("host", "default").block();
        assertThat(host).isNotNull();
        assertThat(host.getDomain()).isEqualTo("default");
        // And a brandx finder does NOT see the seeded default-domain host.
        assertThat(modules.findBySlugAndDomain("host", "brandx").block()).isNull();
    }

    // CROSS-USER: a brand-X module + a brand-Y module with DISTINCT slugs; each
    // brand's finder returns only its own row, never the other's.
    @Test
    void modules_domainPinnedFinder_neverReturnsOtherBrand() {
        modules.save(module("x-only", "brandx")).block();
        modules.save(module("y-only", "brandy")).block();

        assertThat(modules.findBySlugAndDomain("x-only", "brandx").block()).isNotNull();
        // CROSS-USER DENY: x-only queried as brandy is EMPTY.
        assertThat(modules.findBySlugAndDomain("x-only", "brandy").block()).isNull();
        assertThat(modules.findBySlugAndDomain("y-only", "brandx").block()).isNull();

        List<String> brandx = modules.findByDomain("brandx").collectList().block()
                .stream().map(FederationModule::getSlug).toList();
        assertThat(brandx).contains("x-only").doesNotContain("y-only");
    }

    // CROSS-USER: the DOMAIN-scoped manifest finder is the read-path isolation
    // boundary — a brandx manifest query never returns a brandy enabled+closed row.
    @Test
    void manifestFinder_isDomainScoped() {
        modules.save(module("x-manifest", "brandx")).block();
        modules.save(module("y-manifest", "brandy")).block();

        List<String> brandx = modules
                .findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "brandx")
                .collectList().block().stream().map(FederationModule::getSlug).toList();
        assertThat(brandx).contains("x-manifest").doesNotContain("y-manifest");
    }

    // CROSS-USER: federation_override domain-pinned active-scope finder.
    @Test
    void overrides_domainScopedActiveFinder() {
        overrides.save(override("user", "u1", "brandx")).block();
        overrides.save(override("user", "u1", "brandy")).block();

        List<FederationOverride> brandx = overrides
                .findByScopeInAndClearedAtIsNullAndDomain(List.of("all", "user", "role"), "brandx")
                .collectList().block();
        assertThat(brandx).hasSize(1);
        assertThat(brandx.get(0).getDomain()).isEqualTo("brandx");

        List<FederationOverride> brandxList = overrides.findByDomainOrderByTsDesc("brandx")
                .collectList().block();
        assertThat(brandxList).allMatch(o -> "brandx".equals(o.getDomain()));
    }

    // CROSS-USER: moderation_requests domain-pinned id + list finders.
    @Test
    void moderation_domainScopedFinders() {
        ModerationRequest x = moderation.save(request("brandx")).block();
        ModerationRequest y = moderation.save(request("brandy")).block();

        // brand-X cannot load brand-Y's request by id.
        assertThat(moderation.findByIdAndDomain(y.getId(), "brandx").block()).isNull();
        assertThat(moderation.findByIdAndDomain(x.getId(), "brandx").block()).isNotNull();

        List<ModerationRequest> brandx = moderation.findByDomainOrderByTsDesc("brandx")
                .collectList().block();
        assertThat(brandx).allMatch(r -> "brandx".equals(r.getDomain()));
        assertThat(brandx).extracting(ModerationRequest::getId).contains(x.getId()).doesNotContain(y.getId());
    }

    // CONCURRENT: 40 interleaved module saves across two brands; afterwards each
    // brand's finder returns EXACTLY its 20 rows — no cross-domain leakage under
    // contention.
    @Test
    void concurrent_interleavedWrites_stayDomainIsolated() {
        Flux<FederationModule> writes = Flux.fromStream(IntStream.range(0, 40).boxed())
                .flatMap(i -> {
                    String brand = (i % 2 == 0) ? "cbrandx" : "cbrandy";
                    return modules.save(module("c-" + brand + "-" + i, brand));
                }, /* concurrency */ 8);
        StepVerifier.create(writes).expectNextCount(40).verifyComplete();

        List<FederationModule> x = modules.findByDomain("cbrandx").collectList().block();
        List<FederationModule> y = modules.findByDomain("cbrandy").collectList().block();
        assertThat(x).hasSize(20).allMatch(m -> "cbrandx".equals(m.getDomain()));
        assertThat(y).hasSize(20).allMatch(m -> "cbrandy".equals(m.getDomain()));
        // No slug leaks across the boundary.
        assertThat(x).extracting(FederationModule::getSlug)
                .noneMatch(s -> s.contains("cbrandy"));
    }

    private static FederationOverride override(String scope, String target, String domain) {
        FederationOverride o = new FederationOverride();
        o.setScope(scope);
        o.setTarget(target);
        o.setAction("circuit-break");
        o.setSetBy("admin-1");
        o.setDomain(domain);
        o.setTs(Instant.now());
        return o;
    }

    private static ModerationRequest request(String domain) {
        ModerationRequest r = new ModerationRequest();
        r.setRequester("mod-1");
        r.setKind("instance-block");
        r.setTarget("evil.example");
        r.setStatus("recommended");
        r.setDomain(domain);
        r.setTs(Instant.now());
        return r;
    }
}
