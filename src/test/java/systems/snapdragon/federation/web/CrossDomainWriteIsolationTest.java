package systems.snapdragon.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;
import systems.snapdragon.federation.testsupport.TestIssuer;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * WAVE-2c CROSS-DOMAIN WRITE ISOLATION at the HTTP boundary — the gap left
 * service-only by the existing {@code DomainScopedRepositoryTest} (query layer) and
 * {@code DomainAuthzEndpointTest} ({@code mockJwt} ROLE gate only). This drives the
 * REAL {@code ModuleRegistryController} / {@code OverrideController} write surface
 * through the REAL production {@link systems.snapdragon.federation.config.SecurityConfig}
 * filter chain with REAL RS256 per-brand tokens (two in-process {@link TestIssuer}
 * JWKS servers), the REAL {@code @PreAuthorize} method security, the REAL services,
 * and a REAL Liquibase-applied H2 store. NO production code is touched.
 *
 * <p>The cross-domain CUT in this codebase is NOT a 403 (the path gate +
 * {@code @PreAuthorize} only assert the ROLE — a brand-X admin IS an admin): it is a
 * SERVICE-QUERY cut. A per-domain admin's write is loaded pinned to their
 * issuer-derived {@code DOMAIN_<x>} ({@code findBySlugAndDomain}), so a slug owned by
 * another brand resolves EMPTY and the write 404s, leaving the victim row untouched;
 * a create stamps the caller's domain (the request-body {@code domain} is ignored);
 * a clear matches zero foreign rows. Proving that needs the real query against real
 * rows — hence the full {@code @SpringBootTest} with a real DB here.
 *
 * <p><b>Mutation-resistant by construction.</b> The service is NOT mocked, so a DENY
 * assertion is not circular: each cross-domain DENY pairs the HTTP status with a
 * direct DB re-read proving the victim brand's row is UNCHANGED (update/rearm/apply)
 * or that the create landed in the caller's brand, never the body's. If the guard
 * were removed (e.g. {@code findBySlug} instead of {@code findBySlugAndDomain}, or
 * the create trusting the body domain) the foreign row WOULD change / the create
 * WOULD land cross-domain and these tests would FAIL.
 *
 * <p>Delineated per the comprehensive test standard:
 * <ul>
 *   <li><b>CROSS-USER DENY (tenant isolation)</b> — a brand-X admin can NOT
 *       create-into / update / rearm / apply-override-against / clear a brand-Y
 *       resource.</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — a brand-X admin CAN write its OWN brand's
 *       resources (the guard does not over-block).</li>
 *   <li><b>SUPERADMIN cross-domain ALLOW</b> — the infra super-role reaches across
 *       tenants on WRITE: it updates / applies-override-against a brand-Y module and
 *       the brand-Y row DOES change.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureWebTestClient
// NB: deliberately NOT @ActiveProfiles("test") — the multi-issuer swap in
// SecurityConfig.configureResourceServer requires the TenancyResourceServerConfig
// resolver bean, which is @ConditionalOnExpression on app.tenancy.issuers carrying
// '='. We supply that (and the real per-brand issuers) via @DynamicPropertySource
// below, so the PROD resource-server multi-issuer path is exercised end to end.
class CrossDomainWriteIsolationTest {

    private static TestIssuer brandX;
    private static TestIssuer brandY;

    @BeforeAll
    static void issuers() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
    }

    @AfterAll
    static void stop() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        // Real per-brand Casdoor issuers => multi-issuer mode (the prod resolver +
        // OIDC discovery against the in-process JWKS servers). brandX -> DOMAIN_brandx,
        // brandY -> DOMAIN_brandy.
        r.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        // A dedicated H2 store for this class (own Liquibase-applied schema). We run
        // WITHOUT the test profile (so the PROD filter chain is under test), so
        // application.yml's prod username/password (snapdragon) would otherwise be
        // appended on top of the URL's USER=sa => H2 "Duplicate property USER"; pin
        // both R2DBC handles to sa/empty so they match the URL and share the store.
        r.add("spring.r2dbc.url", () ->
                "r2dbc:h2:mem:///fed_xdomain_w2c;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE");
        r.add("spring.r2dbc.username", () -> "sa");
        r.add("spring.r2dbc.password", () -> "");
        r.add("spring.liquibase.url", () ->
                "jdbc:h2:mem:fed_xdomain_w2c;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION;DATABASE_TO_LOWER=TRUE");
        r.add("spring.liquibase.user", () -> "sa");
        r.add("spring.liquibase.password", () -> "");
        // Cassandra OFF -> the noop manifest cache wins (no external infra).
        r.add("app.manifest-cache.cassandra.enabled", () -> "false");
        r.add("app.bundles.storage", () -> "filesystem");
        r.add("app.bundles.dir", () -> System.getProperty("java.io.tmpdir")
                + "/snapdragon-federation-api-w2c-xdomain-bundles");
        // Resource-server autoconfig wiring. We run WITHOUT the test profile so the
        // PROD SecurityConfig#filterChain (@Profile "!dev & !test") is the chain under
        // test. Boot's ReactiveOAuth2ResourceServer autoconfig still eagerly builds a
        // (here UNUSED) jwtDecoder bean from these props, so:
        //   - clear issuer-uri so startup never dials the real public Casdoor (no OIDC
        //     discovery / network egress at boot), and
        //   - give it a dummy jwk-set-uri so the decoder factory has SOMETHING to build
        //     (it is never invoked: SecurityConfig swaps to the multi-issuer resolver
        //      because isMultiIssuer() is true — two trusted issuers above).
        // TenancyResourceServerConfig has no back-compat issuer of its own (its ctor
        // issuer-uri/jwk-set-uri default empty), so every real token is validated by its
        // per-brand decoder via OIDC discovery against the in-process TestIssuer.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    @Autowired WebTestClient web;
    @Autowired FederationModuleRepository modules;
    @Autowired FederationOverrideRepository overrides;

    // Distinct slugs per brand so we can prove a brand-Y row is never touched by a
    // brand-X write (and a brand-X create never lands in brand-Y).
    private static final String Y_MODULE = "y-svc";

    @BeforeEach
    void seed() {
        // Clean any rows a prior method left (shared cached context => shared store).
        modules.deleteAll().block();
        overrides.deleteAll().block();
        // A brand-Y module the brand-X admin must NEVER reach on a write.
        modules.save(module(Y_MODULE, "brandy", "closed", true)).block();
    }

    // Tokens: a brand-scoped ADMIN (issuer-derived DOMAIN_<x>) and a SUPERADMIN.
    private static String adminX() { return brandX.mint("admin-x", List.of("admin")); }
    private static String adminY() { return brandY.mint("admin-y", List.of("admin")); }
    // SUPERADMIN minted by brand-X's issuer: the issuer pins DOMAIN_brandx, but the
    // superadmin role makes the DomainScope cross-domain (no predicate), so it reaches
    // brand-Y rows. (Which brand minted it is irrelevant for the cross-domain reach.)
    private static String superadmin() { return brandX.mint("root", List.of("superadmin")); }

    private WebTestClient.RequestBodySpec post(String uri, String bearer) {
        return web.post().uri(uri).header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }

    private WebTestClient.RequestBodySpec put(String uri, String bearer) {
        return web.put().uri(uri).header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }

    // ───────────────────────── ModuleRegistry POST create ─────────────────────────

    @Test
    void create_brandXAdmin_cannotPlantIntoBrandY_bodyDomainIsIgnored() {
        // Brand-X admin POSTs a module whose BODY claims domain=brandy. The service
        // overwrites domain from the authenticated scope, so the row MUST land in
        // brandx, never brandy.
        post("/api/federation/modules", adminX())
                .bodyValue("""
                        {"slug":"x-create","displayName":"X Create","kind":"remote-shell",
                         "remoteEntryUrl":"http://x-create:8080/remoteEntry.json","version":"1.0.0",
                         "domain":"brandy"}
                        """)
                .exchange()
                .expectStatus().isCreated();

        // MUTATION-RESISTANT: the row exists in brandx and is INVISIBLE to brandy.
        FederationModule landed = modules.findBySlug("x-create").block();
        assertThat(landed).isNotNull();
        assertThat(landed.getDomain())
                .as("body domain=brandy must be ignored; the create lands in the caller's brand")
                .isEqualTo("brandx");
        assertThat(modules.findBySlugAndDomain("x-create", "brandy").block())
                .as("a brand-X create must never be queryable as brand-Y")
                .isNull();
    }

    @Test
    void create_brandXAdmin_intoOwnBrand_isAllowed() {
        // USER-SITUATIONAL ALLOW: the guard does not over-block the caller's own brand.
        post("/api/federation/modules", adminX())
                .bodyValue("""
                        {"slug":"x-own","displayName":"X Own","kind":"remote-shell",
                         "remoteEntryUrl":"http://x-own:8080/remoteEntry.json","version":"1.0.0"}
                        """)
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.slug").isEqualTo("x-own")
                .jsonPath("$.domain").isEqualTo("brandx");
    }

    // ───────────────────────── ModuleRegistry PUT update ─────────────────────────

    @Test
    void update_brandXAdmin_cannotUpdateBrandYModule_404_andRowUnchanged() {
        // CROSS-USER DENY: brand-X admin PUTs against brand-Y's slug. The domain-pinned
        // load resolves empty => 404; the brand-Y row's fields are LEFT UNTOUCHED.
        put("/api/federation/modules/" + Y_MODULE, adminX())
                .bodyValue("""
                        {"displayName":"HIJACKED","enabled":false}
                        """)
                .exchange()
                .expectStatus().isNotFound();

        // MUTATION-RESISTANT: if the guard used findBySlug (not …AndDomain) the PUT
        // would have applied and displayName would now be HIJACKED.
        FederationModule victim = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(victim).isNotNull();
        assertThat(victim.getDisplayName())
                .as("a cross-domain PUT must not mutate the victim brand's row")
                .isNotEqualTo("HIJACKED")
                .isEqualTo(Y_MODULE);
        assertThat(victim.isEnabled()).as("victim row stays enabled").isTrue();
    }

    @Test
    void update_superadmin_canUpdateBrandYModule_200_andRowChanges() {
        // SUPERADMIN cross-domain WRITE ALLOW: the infra super-role reaches the brand-Y
        // module and the PUT takes effect on the brand-Y row.
        put("/api/federation/modules/" + Y_MODULE, superadmin())
                .bodyValue("""
                        {"displayName":"by-superadmin"}
                        """)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.displayName").isEqualTo("by-superadmin")
                .jsonPath("$.domain").isEqualTo("brandy");

        FederationModule changed = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(changed).isNotNull();
        assertThat(changed.getDisplayName())
                .as("superadmin reaches across tenants on a write")
                .isEqualTo("by-superadmin");
    }

    @Test
    void update_brandYAdmin_canUpdateOwnModule_200() {
        // USER-SITUATIONAL ALLOW: brand-Y admin updates its OWN brand-Y module.
        put("/api/federation/modules/" + Y_MODULE, adminY())
                .bodyValue("""
                        {"displayName":"by-owner"}
                        """)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.displayName").isEqualTo("by-owner");
    }

    // ───────────────────────── Override POST /overrides (apply) ─────────────────────────

    @Test
    void applyOverride_brandXAdmin_cannotKillBrandYModule_404_andNoAuditRow() {
        // CROSS-USER DENY: brand-X admin tries to circuit-break brand-Y's module. The
        // module is loaded pinned to brandx => empty => 404. No mutation, no audit row.
        post("/api/federation/overrides", adminX())
                .bodyValue("""
                        {"moduleSlug":"%s","scope":"all","action":"circuit-break"}
                        """.formatted(Y_MODULE))
                .exchange()
                .expectStatus().isNotFound();

        // MUTATION-RESISTANT: the brand-Y module is NOT circuit-broken …
        FederationModule victim = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(victim).isNotNull();
        assertThat(victim.getCircuitState())
                .as("a cross-domain kill-switch must not open the victim's circuit")
                .isEqualTo("closed");
        // … and NO audit override row was recorded in EITHER brand.
        assertThat(overrides.findAllByOrderByTsDesc().collectList().block())
                .as("a denied cross-domain apply records no audit row")
                .isEmpty();
    }

    @Test
    void applyOverride_superadmin_canKillBrandYModule_200_andCircuitOpens() {
        // SUPERADMIN cross-domain DECIDE/WRITE ALLOW: reaches brand-Y's module, opens
        // its circuit, and records the audit row attributed to brand-Y.
        post("/api/federation/overrides", superadmin())
                .bodyValue("""
                        {"moduleSlug":"%s","scope":"all","action":"circuit-break"}
                        """.formatted(Y_MODULE))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.action").isEqualTo("circuit-break")
                .jsonPath("$.domain").isEqualTo("brandy");

        FederationModule killed = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(killed).isNotNull();
        assertThat(killed.getCircuitState())
                .as("superadmin's cross-domain kill opens the brand-Y circuit")
                .isEqualTo("open");
    }

    // ───────────────────────── Override POST /{slug}/rearm ─────────────────────────

    @Test
    void rearm_brandXAdmin_cannotRearmBrandYModule_404_andStaysOpen() {
        // Pre-open the brand-Y module's circuit (a prior kill) directly.
        FederationModule y = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        y.setCircuitState("open");
        y.setEnabled(false);
        modules.save(y).block();

        // CROSS-USER DENY: brand-X admin tries to re-arm brand-Y's module => 404.
        web.post().uri("/api/federation/overrides/" + Y_MODULE + "/rearm")
                .header("Authorization", "Bearer " + adminX())
                .exchange()
                .expectStatus().isNotFound();

        // MUTATION-RESISTANT: brand-Y module stays circuit-open / disabled (a removed
        // guard would have closed+enabled it).
        FederationModule still = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(still.getCircuitState())
                .as("a cross-domain rearm must not recover the victim's circuit")
                .isEqualTo("open");
        assertThat(still.isEnabled()).as("victim stays disabled").isFalse();
    }

    @Test
    void rearm_superadmin_canRearmBrandYModule_200_andCircuitCloses() {
        FederationModule y = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        y.setCircuitState("open");
        y.setEnabled(false);
        modules.save(y).block();

        // SUPERADMIN cross-domain ALLOW: re-arms brand-Y's module.
        web.post().uri("/api/federation/overrides/" + Y_MODULE + "/rearm")
                .header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.circuitState").isEqualTo("closed");

        FederationModule recovered = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(recovered.getCircuitState()).isEqualTo("closed");
        assertThat(recovered.isEnabled()).isTrue();
    }

    // ───────────────────────── Override POST /overrides/clear ─────────────────────────

    @Test
    void clearScope_brandXAdmin_cannotClearBrandYKill_0_andRowStaysActive() {
        // Seed an ACTIVE scope=all kill in brand-Y.
        overrides.save(activeAllKill("brandy")).block();

        // CROSS-USER DENY: brand-X admin clears scope=all. The matched stream is
        // filtered to the brand-X domain, so the brand-Y row is NOT cleared (count 0)
        // and stays ACTIVE (cleared_at IS NULL).
        post("/api/federation/overrides/clear", adminX())
                .bodyValue("""
                        {"scope":"all"}
                        """)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Long.class).isEqualTo(0L);

        // MUTATION-RESISTANT: the brand-Y kill row is still active.
        List<FederationOverride> active = overrides
                .findByScopeAndClearedAtIsNull("all").collectList().block();
        assertThat(active)
                .as("a cross-domain clear must leave the victim brand's kill active")
                .hasSize(1);
        assertThat(active.get(0).getDomain()).isEqualTo("brandy");
        assertThat(active.get(0).getClearedAt()).isNull();
    }

    @Test
    void clearScope_superadmin_canClearBrandYKill_1_andRowCleared() {
        overrides.save(activeAllKill("brandy")).block();

        // SUPERADMIN cross-domain ALLOW: clears the brand-Y kill (count 1).
        post("/api/federation/overrides/clear", superadmin())
                .bodyValue("""
                        {"scope":"all"}
                        """)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Long.class).isEqualTo(1L);

        assertThat(overrides.findByScopeAndClearedAtIsNull("all").collectList().block())
                .as("superadmin cleared the brand-Y kill, no active rows remain")
                .isEmpty();
    }

    @Test
    void clearScope_brandYAdmin_canClearOwnKill_1() {
        // USER-SITUATIONAL ALLOW: brand-Y admin clears its OWN brand's kill.
        overrides.save(activeAllKill("brandy")).block();

        post("/api/federation/overrides/clear", adminY())
                .bodyValue("""
                        {"scope":"all"}
                        """)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Long.class).isEqualTo(1L);
    }

    // ─────────────────── Override POST /overrides/clear-source ───────────────────
    // The suspension-clear (rebuild pt.1) path: rearm the active scope override(s)
    // a given SOURCE tag wrote. The prior endpoint attempt was closed for a
    // cross-tenant gap (it called the un-scoped clearScopeBySource), so these prove
    // the domain cut end-to-end through the real chain + service + DB.

    private static final String SUSPENSION_SOURCE = "access_suspension:42";

    @Test
    void clearSource_brandXAdmin_cannotClearBrandYSuspension_0_andRowStaysActive() {
        // Seed an ACTIVE source-tagged scope=user ban in brand-Y.
        overrides.save(activeUserBan("brandy", "bob", SUSPENSION_SOURCE)).block();

        // CROSS-USER DENY: brand-X admin clears by the (guessed) brand-Y source. The
        // matched stream is filtered to brand-X, so the brand-Y row is NOT cleared
        // (count 0) and stays ACTIVE — the cross-tenant gap that closed the prior PR.
        post("/api/federation/overrides/clear-source", adminX())
                .bodyValue("""
                        {"source":"%s"}
                        """.formatted(SUSPENSION_SOURCE))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Long.class).isEqualTo(0L);

        // MUTATION-RESISTANT: the brand-Y suspension row is still active (never cleared).
        List<FederationOverride> active = overrides
                .findByReasonAndClearedAtIsNull(SUSPENSION_SOURCE).collectList().block();
        assertThat(active)
                .as("a cross-domain clear-source must leave the victim brand's suspension active")
                .hasSize(1);
        assertThat(active.get(0).getDomain()).isEqualTo("brandy");
        assertThat(active.get(0).getClearedAt()).isNull();
    }

    @Test
    void clearSource_brandYAdmin_canClearOwnSuspension_1_andRowCleared() {
        // USER-SITUATIONAL ALLOW: brand-Y admin clears its OWN brand's suspension.
        overrides.save(activeUserBan("brandy", "bob", SUSPENSION_SOURCE)).block();

        post("/api/federation/overrides/clear-source", adminY())
                .bodyValue("""
                        {"source":"%s"}
                        """.formatted(SUSPENSION_SOURCE))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Long.class).isEqualTo(1L);

        assertThat(overrides.findByReasonAndClearedAtIsNull(SUSPENSION_SOURCE).collectList().block())
                .as("the brand-Y admin cleared its own brand's suspension")
                .isEmpty();
    }

    @Test
    void clearSource_superadmin_canClearBrandYSuspension_1_andRowCleared() {
        overrides.save(activeUserBan("brandy", "bob", SUSPENSION_SOURCE)).block();

        // SUPERADMIN cross-domain ALLOW: clears the brand-Y suspension (count 1).
        post("/api/federation/overrides/clear-source", superadmin())
                .bodyValue("""
                        {"source":"%s"}
                        """.formatted(SUSPENSION_SOURCE))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Long.class).isEqualTo(1L);

        assertThat(overrides.findByReasonAndClearedAtIsNull(SUSPENSION_SOURCE).collectList().block())
                .as("superadmin cleared the brand-Y suspension, no active source rows remain")
                .isEmpty();
    }

    // ───────────────────────── fixtures ─────────────────────────

    private static FederationModule module(String slug, String domain, String circuit, boolean enabled) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility("public");
        m.setEnabled(enabled);
        m.setCircuitState(circuit);
        m.setDomain(domain);
        return m;
    }

    private static FederationOverride activeAllKill(String domain) {
        FederationOverride o = new FederationOverride();
        o.setScope("all");
        o.setTarget(null);              // scope=all carries a NULL target
        o.setAction("circuit-break");
        o.setSetBy("seed");
        o.setDomain(domain);
        o.setTs(Instant.now());
        // clearedAt stays NULL => ACTIVE
        return o;
    }

    /** An ACTIVE scope=user ban row tagged with a SOURCE (the access-suspension
     *  write), used by the clear-source cross-tenant tests. */
    private static FederationOverride activeUserBan(String domain, String owner, String source) {
        FederationOverride o = new FederationOverride();
        o.setScope("user");
        o.setTarget(owner);
        o.setAction("unpublish");
        o.setSetBy("seed");
        o.setReason(source);
        o.setDomain(domain);
        o.setTs(Instant.now());
        // clearedAt stays NULL => ACTIVE
        return o;
    }
}
