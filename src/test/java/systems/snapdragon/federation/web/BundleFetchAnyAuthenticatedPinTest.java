package systems.snapdragon.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.federation.testsupport.TestIssuer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * WAVE-2c BEHAVIOUR PIN for the bundle content-hash FETCH endpoint
 * ({@code GET /api/federation/bundles/{contentHash}/files/{*path}}) — the
 * remote-fragment SYNC read. This is INTENTIONALLY any-authenticated: the
 * remote-fragment pods present a (service / any-brand) token and stream a bundle
 * file by its content hash. There is NO owner cut and NO domain cut on the fetch
 * path (unlike the owner-scoped {@code readBody}/{@code delete} and the
 * domain-scoped registry/override surfaces) — a content hash is a capability, and
 * the bytes are identical to whoever holds it.
 *
 * <p>This test PINS that contract through the REAL production
 * {@link systems.snapdragon.federation.config.SecurityConfig} filter chain with
 * REAL RS256 tokens (two in-process {@link TestIssuer} brands), the REAL
 * {@code BundleService} + filesystem storage, and a REAL Liquibase H2 store:
 *
 * <ul>
 *   <li><b>401 anonymous</b> — the {@code authenticated()} floor is a genuine guard:
 *       no token =&gt; 401. (If that floor were ever dropped to {@code permitAll},
 *       this FAILS — the assertion is mutation-resistant against loosening.)</li>
 *   <li><b>200 any authenticated, ANY brand</b> — a brand-X token AND a brand-Y
 *       token (neither the bundle's owner; the row carries no domain) BOTH fetch the
 *       same bytes. This is the pinned cross-tenant-by-content-hash behaviour: if a
 *       future change ADDED an owner / per-domain cut here, the foreign-brand fetch
 *       would 403/404 and this FAILS — so a TIGHTENING is caught (the change-detector
 *       the mission asks for).</li>
 * </ul>
 *
 * <p>Multi-issuer wiring + the no-network resource-server setup mirror
 * {@code CrossDomainWriteIsolationTest}.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class BundleFetchAnyAuthenticatedPinTest extends PostgresTestSupport {

    private static TestIssuer brandX;
    private static TestIssuer brandY;
    private static Path bundlesDir;

    @BeforeAll
    static void issuers() throws Exception {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        bundlesDir = Files.createTempDirectory("fed-w2c-bundle-pin-");
    }

    @AfterAll
    static void stop() {
        if (brandX != null) brandX.close();
        if (brandY != null) brandY.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("app.tenancy.issuers",
                () -> brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy");
        // DB wiring (r2dbc + liquibase, this class's own isolated PG) comes from
        // PostgresTestSupport's @ServiceConnection container — H2 url/user/password dropped.
        r.add("app.manifest-cache.cassandra.enabled", () -> "false");
        r.add("app.bundles.storage", () -> "filesystem");
        r.add("app.bundles.dir", () -> bundlesDir.toString());
        // See CrossDomainWriteIsolationTest: clear issuer-uri (no boot-time discovery),
        // dummy jwk-set-uri so the unused autoconfig decoder builds; the multi-issuer
        // resolver handles every real token.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    // 64 lower-hex chars (ValidationPatterns.CONTENT_HASH) — the bundle's sync key.
    private static final String HASH = "a".repeat(64);
    private static final String ENTRY = "remoteEntry.json";
    private static final String BODY = "{\"name\":\"pinned-bundle\"}";
    private static final String FETCH_URI = "/api/federation/bundles/" + HASH + "/files/" + ENTRY;

    @Autowired WebTestClient web;
    @Autowired UserModuleRepository userModules;

    @BeforeEach
    void seed() throws Exception {
        userModules.deleteAll().block();
        // Stage a real version dir <bundlesDir>/<slug>/<hash>/<entry> the filesystem
        // storage will resolve from the row's versionDir locator.
        Path versionDir = bundlesDir.resolve("pinned-slug").resolve(HASH);
        Files.createDirectories(versionDir);
        Files.writeString(versionDir.resolve(ENTRY), BODY, StandardCharsets.UTF_8);

        UserModule m = new UserModule();
        m.setOwnerUserId("owner-in-some-brand");   // NEITHER brand-X nor brand-Y caller
        m.setSlug("pinned-slug");
        m.setVersionDir("file:" + versionDir);
        m.setEntryFile(ENTRY);
        m.setContentHash(HASH);
        m.setManifestJson("{}");
        m.setVisibility("internal");
        m.setCreatedAt(Instant.now());
        userModules.save(m).block();
    }

    @Test
    void fetch_anonymous_is401_theAuthenticatedFloorHolds() {
        web.get().uri(FETCH_URI)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void fetch_brandXToken_200_returnsBytes() {
        web.get().uri(FETCH_URI)
                .header("Authorization", "Bearer " + brandX.mint("any-x", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo(BODY);
    }

    @Test
    void fetch_brandYToken_alsoGets200_sameBytes_crossTenantByContentHash() {
        // The brand-Y caller is NOT the bundle owner and is a DIFFERENT brand than any
        // domain on the row — yet the fetch succeeds with identical bytes. This is the
        // pinned any-authenticated-by-content-hash behaviour; a future owner/domain cut
        // here would break this assertion (change-detector).
        web.get().uri(FETCH_URI)
                .header("Authorization", "Bearer " + brandY.mint("any-y", List.of("user")))
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo(BODY);
    }

    @Test
    void fetch_authenticated_unknownHash_is404_notAuthFailure() {
        // A well-formed but unknown content hash is a 404 from the service (no row),
        // NOT a 401/403 — proving the auth floor admitted the caller and the miss is a
        // genuine not-found, so a future tightening can't hide behind this case.
        String otherHash = "b".repeat(64);
        web.get().uri("/api/federation/bundles/" + otherHash + "/files/" + ENTRY)
                .header("Authorization", "Bearer " + brandX.mint("any-x", List.of("user")))
                .exchange()
                .expectStatus().isNotFound();
    }
}
