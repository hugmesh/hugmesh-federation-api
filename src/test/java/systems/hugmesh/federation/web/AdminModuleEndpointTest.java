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
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.federation.model.FederationManifestDto;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.repository.FederationModuleRepository;
import systems.hugmesh.federation.testsupport.TestIssuer;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FULL-CONTEXT contract proof for the SUPERADMIN admin-modules surface
 * ({@code /api/federation/admin/modules}) — the REAL
 * {@code AdminModuleController} through the REAL production
 * {@link systems.hugmesh.federation.config.SecurityConfig} filter chain
 * (deliberately NOT {@code @ActiveProfiles("test")}) with REAL RS256 per-brand
 * tokens (two in-process {@link TestIssuer} JWKS servers), the REAL
 * {@code @PreAuthorize} method gate, the REAL {@code AdminModuleService} write
 * guards, and a REAL Liquibase-applied Postgres store. Nothing mocked.
 *
 * <p>The {@code CrossDomainWriteIsolationTest} crib, pointed at the wizard
 * surface. brand-X maps to {@code default} on purpose: a SUPERADMIN write lands
 * in {@code domain="default"}, so a plain brand-X user's manifest is the read
 * view a wizard-provisioned module actually serves into — which is what the
 * soft-disable test needs to prove the row VANISHES from.
 *
 * <p>Delineated per the comprehensive test standard:
 * <ul>
 *   <li><b>ANONYMOUS DENY</b> — 401 on every verb, no credentials;</li>
 *   <li><b>CROSS-USER DENY (role narrowness)</b> — a per-brand ADMIN is 403 on
 *       every verb AND (mutation-resistant, victim-creates-first) the
 *       superadmin-owned row is proven byte-unchanged after the denied
 *       hijack/disable attempts;</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — superadmin create-with-defaults,
 *       refresh-in-place (id stable, omitted {@code enabled} untouched),
 *       full-registry list, soft-disable;</li>
 *   <li><b>VALIDATION DENY</b> — bad slug / kind / URL / visibility and the
 *       reserved {@code profile-*} + malformed-metadata service guards each 400
 *       at the HTTP boundary, with repo re-reads proving nothing persisted;</li>
 *   <li><b>MANIFEST INTERPLAY</b> — the soft-disabled row stops serving in the
 *       REAL {@code GET /api/federation/manifest} while staying in the admin
 *       list.</li>
 * </ul>
 *
 * <p>Every DENY pairs the HTTP status with a direct repository re-read; no
 * sleeps anywhere (WebTestClient + {@code .block()} reads).
 */
@SpringBootTest
@AutoConfigureWebTestClient
// NB: deliberately NOT @ActiveProfiles("test") — the PROD filter chain (and the
// multi-issuer resolver, supplied via @DynamicPropertySource below) is under test.
class AdminModuleEndpointTest extends PostgresTestSupport {

    private static final String COLLECTION = "/api/federation/admin/modules";

    private static TestIssuer brandDefault; // maps to "default" — where SUPERADMIN writes land
    private static TestIssuer brandY;       // a second brand, so isMultiIssuer() holds

    @BeforeAll
    static void issuers() {
        brandDefault = new TestIssuer();
        brandY = new TestIssuer();
    }

    @AfterAll
    static void stop() {
        if (brandDefault != null) brandDefault.close();
        if (brandY != null) brandY.close();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        // brandDefault -> DOMAIN_default: a plain user minted there reads the
        // domain="default" manifest — the view a SUPERADMIN-provisioned module
        // serves into. brandY exists so the multi-issuer resolver engages.
        r.add("app.tenancy.issuers",
                () -> brandDefault.issuerUri() + "=default," + brandY.issuerUri() + "=brandy");
        r.add("app.manifest-cache.cassandra.enabled", () -> "false");
        r.add("app.bundles.storage", () -> "filesystem");
        r.add("app.bundles.dir", () -> System.getProperty("java.io.tmpdir")
                + "/hugmesh-federation-api-admin-modules-bundles");
        // Blank the real-Casdoor issuer / give the (unused) autoconfig decoder a
        // dummy JWKS — see CrossDomainWriteIsolationTest for the full rationale.
        r.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> "");
        r.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri", () -> "http://127.0.0.1:0/jwks");
    }

    @Autowired WebTestClient web;
    @Autowired FederationModuleRepository modules;

    @BeforeEach
    void clean() {
        // Clean any rows a prior method (or the Liquibase seeds) left — the
        // assertions below still use contains/doesNotContain, never absolute counts.
        modules.deleteAll().block();
    }

    private static String superadmin() { return brandDefault.mint("root", List.of("superadmin")); }
    private static String admin() { return brandDefault.mint("brand-admin", List.of("admin")); }
    private static String user() { return brandDefault.mint("plain-user", List.of("user")); }

    private WebTestClient.RequestBodySpec post(String bearer) {
        return web.post().uri(COLLECTION).header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }

    private WebTestClient.ResponseSpec upsert(String bearer, String json) {
        return post(bearer).bodyValue(json).exchange();
    }

    private List<String> manifestSlugsAsUser() {
        FederationManifestDto dto = web.get().uri("/api/federation/manifest")
                .header("Authorization", "Bearer " + user())
                .exchange().expectStatus().isOk()
                .expectBody(FederationManifestDto.class).returnResult().getResponseBody();
        return dto.remotes().stream().map(FederationManifestDto.FederationRemoteDto::slug).toList();
    }

    // ───────────────────────── ANONYMOUS DENY ─────────────────────────

    @Test
    void anonymous_is401_onEveryVerb() {
        web.get().uri(COLLECTION).exchange().expectStatus().isUnauthorized();
        web.post().uri(COLLECTION).contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}").exchange().expectStatus().isUnauthorized();
        web.delete().uri(COLLECTION + "/some-slug").exchange().expectStatus().isUnauthorized();
    }

    // ───────────────────────── CROSS-USER DENY (ADMIN is not enough) ─────────────────────────

    @Test
    void brandAdmin_is403_onEveryVerb_andVictimRowUnchanged() {
        // VICTIM-CREATES-FIRST: the superadmin owns a live wizard row …
        upsert(superadmin(), """
                {"slug":"victim-svc","displayName":"Victim","remoteEntryUrl":
                 "http://victim-svc:8080/remoteEntry.json","exposedModule":"./routes",
                 "visibility":"public","enabled":true}
                """)
                .expectStatus().isOk();

        String admin = admin();
        // … a per-brand ADMIN (who freely reaches /api/federation/modules) is 403
        // on the cross-brand admin surface, on every verb:
        web.get().uri(COLLECTION).header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isForbidden();
        upsert(admin, """
                {"slug":"victim-svc","displayName":"HIJACKED","remoteEntryUrl":
                 "http://evil:8080/remoteEntry.json","exposedModule":"./evil","enabled":false}
                """)
                .expectStatus().isForbidden();
        web.delete().uri(COLLECTION + "/victim-svc").header("Authorization", "Bearer " + admin)
                .exchange().expectStatus().isForbidden();

        // MUTATION-RESISTANT: the victim row is byte-unchanged by the denied
        // hijack-upsert AND the denied disable.
        FederationModule victim = modules.findBySlug("victim-svc").block();
        assertThat(victim).isNotNull();
        assertThat(victim.getDisplayName()).isEqualTo("Victim");
        assertThat(victim.getRemoteEntryUrl()).isEqualTo("http://victim-svc:8080/remoteEntry.json");
        assertThat(victim.getExposedModule()).isEqualTo("./routes");
        assertThat(victim.isEnabled())
                .as("a denied admin DELETE must not soft-disable the row")
                .isTrue();
    }

    // ───────────────────────── ALLOW: create with defaults ─────────────────────────

    @Test
    void superadmin_upsertCreate_landsWithAdminSurfaceDefaults() {
        upsert(superadmin(), """
                {"slug":"wizard-new","remoteEntryUrl":"https://wizard-new:8443/remoteEntry.json",
                 "exposedModule":"./routes"}
                """)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.slug").isEqualTo("wizard-new")
                .jsonPath("$.domain").isEqualTo("default");

        // MUTATION-RESISTANT: re-read through the repository, not the response.
        FederationModule row = modules.findBySlug("wizard-new").block();
        assertThat(row).isNotNull();
        assertThat(row.getKind()).as("kind defaults to remote-shell").isEqualTo("remote-shell");
        assertThat(row.getDisplayName()).as("displayName defaults to the slug").isEqualTo("wizard-new");
        assertThat(row.getVersion()).isEqualTo("1.0.0");
        assertThat(row.getVisibility()).as("a fresh federated service is dark").isEqualTo("internal");
        assertThat(row.isEnabled()).as("enabled defaults to false").isFalse();
        assertThat(row.getCircuitState()).isEqualTo("closed");
        assertThat(row.getDomain()).as("SUPERADMIN write lands in 'default'").isEqualTo("default");
    }

    // ───────────────────────── ALLOW: refresh in place ─────────────────────────

    @Test
    void superadmin_reUpsert_refreshesInPlace_omittedEnabledUntouched() {
        upsert(superadmin(), """
                {"slug":"wizard-upd","displayName":"First","kind":"remote-shell",
                 "remoteEntryUrl":"http://one:8080/remoteEntry.json","exposedModule":"./routes",
                 "version":"1.0.0","visibility":"public","enabled":true}
                """)
                .expectStatus().isOk();
        FederationModule first = modules.findBySlug("wizard-upd").block();
        Long id = first.getId();
        Instant createdAt = first.getCreatedAt();

        // Refresh with displayName/visibility/enabled OMITTED: the required URL +
        // exposedModule move, everything omitted survives — in particular enabled
        // must STAY true (the FederationModule primitive-boolean trap the dedicated
        // request DTO exists to fix).
        upsert(superadmin(), """
                {"slug":"wizard-upd","remoteEntryUrl":"http://two:9090/remoteEntry.json",
                 "exposedModule":"./federated","version":"1.1.0"}
                """)
                .expectStatus().isOk()
                .expectBody().jsonPath("$.id").isEqualTo(id);

        FederationModule row = modules.findBySlug("wizard-upd").block();
        assertThat(row.getId()).as("refresh is in place — same row").isEqualTo(id);
        // Exact equality on purpose — also the real-Postgres regression proof for
        // the zone-symmetric Instant writing converter (R2dbcConvertersConfig):
        // without it this save+read round-trip shifts createdAt by the host's UTC
        // offset (caught live on a UTC-7 host).
        assertThat(row.getCreatedAt()).as("createdAt never moves").isEqualTo(createdAt);
        assertThat(row.getRemoteEntryUrl()).isEqualTo("http://two:9090/remoteEntry.json");
        assertThat(row.getExposedModule()).isEqualTo("./federated");
        assertThat(row.getVersion()).isEqualTo("1.1.0");
        assertThat(row.getDisplayName()).as("omitted displayName kept").isEqualTo("First");
        assertThat(row.getVisibility()).as("omitted visibility kept").isEqualTo("public");
        assertThat(row.isEnabled())
                .as("an upsert body OMITTING enabled must NOT silently disable the module")
                .isTrue();
    }

    // ───────────────────────── ALLOW: full-registry list ─────────────────────────

    @Test
    void superadmin_list_isTheFullRegistryState_disabledInternalForeignIncluded() {
        modules.save(row("adm-disabled", "default", "public", false)).block();
        modules.save(row("adm-internal", "default", "internal", true)).block();
        modules.save(row("adm-foreign", "brandy", "public", true)).block();

        web.get().uri(COLLECTION).header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(FederationModule.class)
                .value(list -> assertThat(list)
                        .extracting(FederationModule::getSlug)
                        .as("the admin list is the FULL registry — no enabled/visibility/domain cut")
                        .contains("adm-disabled", "adm-internal", "adm-foreign"));
    }

    // ───────────────────────── VALIDATION DENY (HTTP boundary) ─────────────────────────

    @Test
    void upsert_missingRequiredFields_is400_withHouseFieldErrors() {
        upsert(superadmin(), "{}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.slug").exists()
                .jsonPath("$.fields.remoteEntryUrl").exists()
                .jsonPath("$.fields.exposedModule").exists();
    }

    @Test
    void upsert_badSlug_badKind_badUrl_badVisibility_each400_nothingPersisted() {
        // Non-DNS-label slug.
        upsert(superadmin(), """
                {"slug":"Bad_Slug","remoteEntryUrl":"http://x:1/r.json","exposedModule":"./routes"}
                """)
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.slug").exists();
        // kind outside the wizard vocabulary (host is the shell, never provisioned here).
        upsert(superadmin(), """
                {"slug":"bad-kind","kind":"host","remoteEntryUrl":"http://x:1/r.json",
                 "exposedModule":"./routes"}
                """)
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.kind").exists();
        // Non-http(s) remoteEntryUrl (DTO pattern leg; the service URI re-parse is
        // proven in AdminModuleServiceTest).
        upsert(superadmin(), """
                {"slug":"bad-url","remoteEntryUrl":"ftp://host/r.json","exposedModule":"./routes"}
                """)
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.remoteEntryUrl").exists();
        // visibility outside public|internal.
        upsert(superadmin(), """
                {"slug":"bad-vis","remoteEntryUrl":"http://x:1/r.json","exposedModule":"./routes",
                 "visibility":"secret"}
                """)
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.visibility").exists();

        for (String slug : List.of("bad-kind", "bad-url", "bad-vis")) {
            assertThat(modules.findBySlug(slug).block())
                    .as("a rejected upsert persists nothing (" + slug + ")").isNull();
        }
    }

    @Test
    void upsert_reservedProfileSlug_is400_nothingPersisted() {
        upsert(superadmin(), """
                {"slug":"profile-alice","remoteEntryUrl":"http://x:1/r.json",
                 "exposedModule":"./routes"}
                """)
                .expectStatus().isBadRequest();
        assertThat(modules.findBySlug("profile-alice").block())
                .as("profile-* slugs belong exclusively to the vanity publish path").isNull();
    }

    @Test
    void upsert_malformedMetadata_is400_nothingPersisted() {
        upsert(superadmin(), """
                {"slug":"bad-meta","remoteEntryUrl":"http://x:1/r.json","exposedModule":"./routes",
                 "metadata":"{nope"}
                """)
                .expectStatus().isBadRequest();
        upsert(superadmin(), """
                {"slug":"bad-meta","remoteEntryUrl":"http://x:1/r.json","exposedModule":"./routes",
                 "metadata":"{\\"mountAt\\":\\"no-slash\\"}"}
                """)
                .expectStatus().isBadRequest();
        assertThat(modules.findBySlug("bad-meta").block())
                .as("no metadata rejection ever persists a row").isNull();
    }

    @Test
    void softDisable_badSlugPathVariable_is400_houseMessage() {
        web.delete().uri(COLLECTION + "/Bad_Slug").header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed");
    }

    // ───────────────────────── soft-disable + manifest interplay ─────────────────────────

    @Test
    void softDisable_204_rowStays_manifestDropsIt_adminListKeepsIt() {
        // A live public module, provisioned through the real endpoint with the
        // house metadata convention …
        upsert(superadmin(), """
                {"slug":"wizard-live","displayName":"Live","remoteEntryUrl":
                 "http://wizard-live:8080/remoteEntry.json","exposedModule":"./routes",
                 "visibility":"public","enabled":true,
                 "metadata":"{\\"mountAt\\":\\"/wizard-live\\"}"}
                """)
                .expectStatus().isOk();
        // … SANITY (ALLOW leg): it serves in a plain default-domain user's manifest.
        assertThat(manifestSlugsAsUser()).contains("wizard-live");

        web.delete().uri(COLLECTION + "/wizard-live")
                .header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isNoContent();

        // The row STAYS (soft-disable, never a delete), ONLY enabled flipped.
        FederationModule row = modules.findBySlug("wizard-live").block();
        assertThat(row).as("soft-disable never deletes the row").isNotNull();
        assertThat(row.isEnabled()).isFalse();
        assertThat(row.getVisibility()).as("visibility untouched").isEqualTo("public");
        assertThat(row.getCircuitState()).as("circuit untouched").isEqualTo("closed");

        // MANIFEST INVARIANT: the REAL read path no longer serves the slug …
        assertThat(manifestSlugsAsUser())
                .as("a soft-disabled module vanishes from the manifest (DB-side enabled cut)")
                .doesNotContain("wizard-live");
        // … while the admin list (full registry state) still shows it, disabled.
        web.get().uri(COLLECTION).header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(FederationModule.class)
                .value(list -> assertThat(list)
                        .filteredOn(m -> "wizard-live".equals(m.getSlug()))
                        .singleElement()
                        .satisfies(m -> assertThat(m.isEnabled()).isFalse()));
    }

    @Test
    void softDisable_absentSlug_is404() {
        web.delete().uri(COLLECTION + "/wizard-nope")
                .header("Authorization", "Bearer " + superadmin())
                .exchange()
                .expectStatus().isNotFound();
    }

    // ───────────────────────── fixtures ─────────────────────────

    private static FederationModule row(String slug, String domain, String visibility, boolean enabled) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility(visibility);
        m.setEnabled(enabled);
        m.setCircuitState("closed");
        m.setDomain(domain);
        m.setCreatedAt(Instant.now());
        m.setUpdatedAt(Instant.now());
        return m;
    }
}
