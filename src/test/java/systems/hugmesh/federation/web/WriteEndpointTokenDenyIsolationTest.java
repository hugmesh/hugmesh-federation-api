package systems.hugmesh.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.repository.FederationModuleRepository;
import systems.hugmesh.federation.repository.FederationOverrideRepository;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.federation.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RAW-API-DENY negative security suite for the federation WRITE surface — the
 * credential-quality deny-legs the existing exemplars leave open. Sibling of
 * {@link CrossDomainWriteIsolationTest} (which proves the CROSS-DOMAIN/tenant cut on
 * writes) and {@link FederationHttpAuthzE2eTest} (which proves the unknown-issuer cut
 * but only on the READ {@code /manifest} surface). This class drives the SAME REAL
 * production {@link systems.hugmesh.federation.config.SecurityConfig} multi-issuer
 * filter chain, REAL {@code @PreAuthorize} method security, REAL services and a REAL
 * Liquibase-applied H2 store, against the {@code modules} / {@code overrides} WRITE
 * endpoints — with three classes of BAD credential that must each be REJECTED at the
 * resource-server decoder BEFORE the controller ever runs:
 *
 * <ol>
 *   <li><b>FOREIGN-ISSUER token at a WRITE</b> — a perfectly-formed, correctly-signed
 *       admin/superadmin token whose {@code iss} is NOT in {@code app.tenancy.issuers}.
 *       The per-issuer resolver returns empty =&gt; 401, fail-closed. (The existing
 *       suite only proves this on GET /manifest; here it is proven on POST/PUT writes,
 *       where a fail-OPEN would mutate state.)</li>
 *   <li><b>EXPIRED token at a WRITE</b> — a token minted by a TRUSTED brand with a
 *       superadmin role but whose {@code exp} is in the past. The JWT timestamp
 *       validator rejects it =&gt; 401. A lapsed credential can never write.</li>
 *   <li><b>REVOKED-but-structurally-valid token at a WRITE</b> — a trusted-brand
 *       superadmin token that is correctly formatted, carries a trusted {@code iss}
 *       and is UNEXPIRED, but was signed by a key the issuer has since ROTATED away
 *       (server-side credential revocation / key de-provisioning). Its signature no
 *       longer verifies against the issuer's live JWKS =&gt; 401.</li>
 * </ol>
 *
 * <p><b>Mutation-resistant by construction.</b> The service + DB are REAL, not mocked,
 * so every DENY is paired with a direct DB re-read proving NOTHING was written: the
 * victim brand-Y module row is unchanged (display name, enabled, circuit state) and NO
 * override audit row was recorded in EITHER brand. If the decoder ever fail-OPENED on
 * any of these bad credentials, the superadmin role the tokens carry would let the
 * write LAND and these re-reads would fail loudly.
 *
 * <p>The tokens all carry {@code superadmin} deliberately: superadmin is the ONE role
 * that, IF authenticated, reaches across tenants on a write (see
 * {@link CrossDomainWriteIsolationTest}'s superadmin ALLOW legs). So a leak here is
 * maximally damaging — proving the deny holds for the most privileged role proves it
 * a fortiori for the rest.
 *
 * <p>Delineated per the comprehensive test standard: all legs are CROSS-USER / DENY
 * (the authentication boundary — an untrusted, lapsed or revoked credential can never
 * cross in to mutate state). NO production code is changed (src/test only).
 */
@SpringBootTest
@AutoConfigureWebTestClient
// Deliberately NOT @ActiveProfiles("test") — like CrossDomainWriteIsolationTest, we
// exercise the PROD SecurityConfig#filterChain (@Profile "!dev & !test") so the real
// multi-issuer resource-server path is under test end to end.
class WriteEndpointTokenDenyIsolationTest extends PostgresTestSupport {

    private static TestIssuer brandX;   // trusted -> DOMAIN_brandx
    private static TestIssuer brandY;   // trusted -> DOMAIN_brandy
    private static TestIssuer rogue;    // well-formed + signed, but NOT trusted
    private static TestIssuer revoked;  // trusted at config time; key rotated before any validation

    @BeforeAll
    static void issuers() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();
        revoked = new TestIssuer();
    }

    @AfterAll
    static void stop() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
        if (rogue != null) rogue.close();
        if (revoked != null) revoked.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        // brandX + brandY + revoked are all TRUSTED (three '=' pairs => multi-issuer).
        // `revoked` is trusted by config, but we mint a token then rotate its signing
        // key BEFORE the request, so the token's signature no longer matches the JWKS
        // the issuer now serves — a structurally-valid-but-revoked credential.
        // `rogue` is deliberately ABSENT from the allowlist (the foreign-issuer leg).
        r.add("app.tenancy.issuers", () ->
                brandX.issuerUri() + "=brandx,"
                        + brandY.issuerUri() + "=brandy,"
                        + revoked.issuerUri() + "=revokedbrand");
        // DB wiring (r2dbc + liquibase, this class's own isolated PG) comes from
        // PostgresTestSupport's @ServiceConnection container — the H2 url/user/password
        // lines were dropped. We run WITHOUT the test profile, so the non-DB infra props
        // (cassandra-off, filesystem bundles, dummy jwt uris) stay set explicitly here.
        r.add("app.manifest-cache.cassandra.enabled", () -> "false");
        r.add("app.bundles.storage", () -> "filesystem");
        r.add("app.bundles.dir", () -> System.getProperty("java.io.tmpdir")
                + "/hugmesh-federation-api-write-token-deny-bundles");
        // Boot still eagerly builds an (unused) default jwtDecoder bean from these:
        // blank issuer-uri so startup never dials a real Casdoor; dummy jwk-set-uri so
        // the decoder factory has something to build (never invoked — the multi-issuer
        // resolver wins because isMultiIssuer() is true above).
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    @Autowired WebTestClient web;
    @Autowired FederationModuleRepository modules;
    @Autowired FederationOverrideRepository overrides;

    private static final String Y_MODULE = "y-svc-tokendeny";

    @BeforeEach
    void seed() {
        modules.deleteAll().block();
        overrides.deleteAll().block();
        // The brand-Y victim row a bad-credential write must NEVER touch.
        modules.save(module(Y_MODULE, "brandy", "closed", true)).block();
    }

    // ── credentials ────────────────────────────────────────────────────────────
    // A FOREIGN-issuer superadmin token (untrusted iss).
    private static String foreignSuperadmin() { return rogue.mint("attacker", List.of("admin", "superadmin")); }
    // An EXPIRED superadmin token from a TRUSTED brand (exp in the past).
    private static String expiredSuperadmin() { return brandX.mintExpired("admin-x", List.of("admin", "superadmin")); }

    private WebTestClient.RequestBodySpec post(String uri, String bearer) {
        return web.post().uri(uri).header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }

    private WebTestClient.RequestBodySpec put(String uri, String bearer) {
        return web.put().uri(uri).header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }

    private void assertVictimUntouched() {
        FederationModule victim = modules.findBySlugAndDomain(Y_MODULE, "brandy").block();
        assertThat(victim).as("victim brand-Y row still present").isNotNull();
        assertThat(victim.getDisplayName())
                .as("a denied write must not mutate the victim row")
                .isEqualTo(Y_MODULE);
        assertThat(victim.isEnabled()).as("victim stays enabled").isTrue();
        assertThat(victim.getCircuitState()).as("victim circuit stays closed").isEqualTo("closed");
    }

    private void assertNothingCreated() {
        assertThat(modules.findBySlug("planted").block())
                .as("a denied create must not land any row").isNull();
        assertThat(overrides.findAllByOrderByTsDesc().collectList().block())
                .as("a denied override write records no audit row").isEmpty();
    }

    // ════════════════════ (1) FOREIGN-ISSUER token at a WRITE ════════════════════

    @Test
    void foreignIssuer_createModule_is401_andNothingPlanted() {
        post("/api/federation/modules", foreignSuperadmin())
                .bodyValue("""
                        {"slug":"planted","displayName":"PLANTED","kind":"remote-shell",
                         "remoteEntryUrl":"http://planted:8080/remoteEntry.json","version":"1.0.0"}
                        """)
                .exchange()
                .expectStatus().isUnauthorized();
        assertNothingCreated();
    }

    @Test
    void foreignIssuer_updateBrandYModule_is401_andRowUnchanged() {
        put("/api/federation/modules/" + Y_MODULE, foreignSuperadmin())
                .bodyValue("""
                        {"displayName":"HIJACKED","enabled":false}
                        """)
                .exchange()
                .expectStatus().isUnauthorized();
        assertVictimUntouched();
    }

    @Test
    void foreignIssuer_applyOverride_is401_andNoCircuitOpen_noAudit() {
        post("/api/federation/overrides", foreignSuperadmin())
                .bodyValue("""
                        {"moduleSlug":"%s","scope":"all","action":"circuit-break"}
                        """.formatted(Y_MODULE))
                .exchange()
                .expectStatus().isUnauthorized();
        assertVictimUntouched();
        assertNothingCreated();
    }

    // ════════════════════ (2) EXPIRED token at a WRITE ═══════════════════════════

    @Test
    void expired_createModule_is401_andNothingPlanted() {
        post("/api/federation/modules", expiredSuperadmin())
                .bodyValue("""
                        {"slug":"planted","displayName":"PLANTED","kind":"remote-shell",
                         "remoteEntryUrl":"http://planted:8080/remoteEntry.json","version":"1.0.0"}
                        """)
                .exchange()
                .expectStatus().isUnauthorized();
        assertNothingCreated();
    }

    @Test
    void expired_updateBrandYModule_is401_andRowUnchanged() {
        put("/api/federation/modules/" + Y_MODULE, expiredSuperadmin())
                .bodyValue("""
                        {"displayName":"HIJACKED","enabled":false}
                        """)
                .exchange()
                .expectStatus().isUnauthorized();
        assertVictimUntouched();
    }

    @Test
    void expired_applyOverride_is401_andNoCircuitOpen_noAudit() {
        post("/api/federation/overrides", expiredSuperadmin())
                .bodyValue("""
                        {"moduleSlug":"%s","scope":"all","action":"circuit-break"}
                        """.formatted(Y_MODULE))
                .exchange()
                .expectStatus().isUnauthorized();
        assertVictimUntouched();
        assertNothingCreated();
    }

    // ════════ (3) REVOKED-but-structurally-valid (orphan-signed) at a WRITE ════════
    // `revoked` is a TRUSTED issuer (in app.tenancy.issuers), but mintRevoked signs the
    // token with a fresh keypair whose kid the issuer's JWKS NEVER serves — a
    // de-provisioned / rotated-away credential. The token is well-formed, carries the
    // trusted iss and is unexpired, yet its signature cannot verify against the live
    // JWKS => 401, deterministically (the orphan kid misses on every fetch).

    private static String revokedSuperadmin() { return revoked.mintRevoked("ex-admin", List.of("admin", "superadmin")); }

    @Test
    void revokedKey_createModule_is401_andNothingPlanted() {
        post("/api/federation/modules", revokedSuperadmin())
                .bodyValue("""
                        {"slug":"planted","displayName":"PLANTED","kind":"remote-shell",
                         "remoteEntryUrl":"http://planted:8080/remoteEntry.json","version":"1.0.0"}
                        """)
                .exchange()
                .expectStatus().isUnauthorized();
        assertNothingCreated();
    }

    @Test
    void revokedKey_updateBrandYModule_is401_andRowUnchanged() {
        put("/api/federation/modules/" + Y_MODULE, revokedSuperadmin())
                .bodyValue("""
                        {"displayName":"HIJACKED","enabled":false}
                        """)
                .exchange()
                .expectStatus().isUnauthorized();
        assertVictimUntouched();
    }

    @Test
    void revokedKey_applyOverride_is401_andNoCircuitOpen_noAudit() {
        post("/api/federation/overrides", revokedSuperadmin())
                .bodyValue("""
                        {"moduleSlug":"%s","scope":"all","action":"circuit-break"}
                        """.formatted(Y_MODULE))
                .exchange()
                .expectStatus().isUnauthorized();
        assertVictimUntouched();
        assertNothingCreated();
    }

    // ── fixtures ─────────────────────────────────────────────────────────────────

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
}
