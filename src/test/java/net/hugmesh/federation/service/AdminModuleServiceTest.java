package net.hugmesh.federation.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.federation.cache.ManifestCache;
import net.hugmesh.federation.config.R2dbcConvertersConfig;
import net.hugmesh.federation.model.AdminModuleUpsertRequest;
import net.hugmesh.federation.model.FederationManifestDto;
import net.hugmesh.federation.model.FederationModule;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.federation.repository.FederationOverrideRepository;
import net.hugmesh.federation.support.TestDatabaseConfig;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link AdminModuleService} behaviour over the REAL Liquibase-applied DDL (H2
 * PostgreSQL-compat via {@link TestDatabaseConfig}) — the upsert-by-slug /
 * soft-disable semantics, every service-side write guard, and the
 * MANIFEST-INVARIANT interplay proven against the REAL
 * {@link ManifestService} + repositories (nothing mocked but the noop cache).
 *
 * <p>Delineated per the platform test standard:
 * <ul>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — a superadmin upsert creates with the
 *       admin-surface defaults; a re-upsert refreshes IN PLACE (id/createdAt/
 *       domain/circuitState stable, {@code enabled} untouched when omitted);
 *       soft-disable flips {@code enabled} only and keeps the row;</li>
 *   <li><b>DENY (write guards)</b> — reserved {@code profile-*} slug, non-http(s)
 *       remoteEntryUrl, malformed metadata each 400 AND (mutation-resistant) a
 *       repo re-read proves NOTHING was persisted;</li>
 *   <li><b>MANIFEST INTERPLAY</b> — a soft-disabled row vanishes from the REAL
 *       manifest render (DB-side enabled predicate); an upsert on a circuit-open
 *       row never closes the circuit, so a circuit-break kill survives wizard
 *       re-POSTs; well-shaped metadata written here is exactly what
 *       {@code ManifestService.requiresRole} reads back.</li>
 * </ul>
 *
 * <p>Every assertion re-reads through the repository (not the returned DTO), so a
 * broken save cannot self-certify. No sleeps anywhere — H2 + {@code .block()}.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
// Force an OWN cached context + OWN H2 store (this class deletes + writes
// federation_modules rows that would break the shared-store slice classes'
// absolute-count assertions) — the DomainScopedRepositoryTest convention.
@TestPropertySource(properties = "test.context = admin-module-service")
class AdminModuleServiceTest {

    private static final PrincipalDomain SUPER = PrincipalDomain.superadminFor(null);

    @Autowired FederationModuleRepository modules;
    @Autowired FederationOverrideRepository overrides;

    private AdminModuleService service;
    private ManifestService manifest;

    @BeforeEach
    void setUp() {
        service = new AdminModuleService(modules);
        manifest = new ManifestService(modules, overrides, noopCache());
        // Clean slate (seeds included) — safe because the @TestPropertySource above
        // gives this class its OWN cached context + OWN H2 store; the assertions
        // below still use contains/doesNotContain, never absolute counts.
        modules.deleteAll().block();
        overrides.deleteAll().block();
    }

    private static ManifestCache noopCache() {
        return new ManifestCache() {
            @Override public Mono<Void> put(String domain, FederationManifestDto m) { return Mono.empty(); }
            @Override public Mono<FederationManifestDto> get(String domain) { return Mono.empty(); }
            @Override public Mono<Void> invalidate(String domain) { return Mono.empty(); }
            @Override public String label() { return "noop"; }
        };
    }

    /** Minimal valid wizard payload for {@code slug} — only the required fields. */
    private static AdminModuleUpsertRequest minimal(String slug) {
        return new AdminModuleUpsertRequest(slug, null, null,
                "http://" + slug + ":8080/remoteEntry.json", "./routes",
                null, null, null, null);
    }

    private static AdminModuleUpsertRequest request(String slug, String displayName, String kind,
                                                    String remoteEntryUrl, String exposedModule,
                                                    String version, String visibility, Boolean enabled,
                                                    String metadata) {
        return new AdminModuleUpsertRequest(slug, displayName, kind, remoteEntryUrl, exposedModule,
                version, visibility, enabled, metadata);
    }

    private void expect400(AdminModuleUpsertRequest req) {
        StepVerifier.create(service.upsert(req, SUPER))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode().value())
                            .as("write-guard rejections are 400").isEqualTo(400);
                })
                .verify();
    }

    // ───────────────────────── upsert: create ─────────────────────────

    @Test
    void upsert_createsWithAdminSurfaceDefaults_andStampsDefaultDomain() {
        FederationModule returned = service.upsert(minimal("wizard-svc"), SUPER).block();
        assertThat(returned).isNotNull();
        assertThat(returned.getId()).isNotNull();

        // MUTATION-RESISTANT: re-read through the repository, not the return value.
        FederationModule row = modules.findBySlug("wizard-svc").block();
        assertThat(row).isNotNull();
        assertThat(row.getDisplayName()).as("displayName defaults to the slug").isEqualTo("wizard-svc");
        assertThat(row.getKind()).as("kind defaults to remote-shell").isEqualTo("remote-shell");
        assertThat(row.getRemoteEntryUrl()).isEqualTo("http://wizard-svc:8080/remoteEntry.json");
        assertThat(row.getExposedModule()).isEqualTo("./routes");
        assertThat(row.getVersion()).as("version defaults to 1.0.0").isEqualTo("1.0.0");
        assertThat(row.getVisibility()).as("a fresh federated service is dark").isEqualTo("internal");
        assertThat(row.isEnabled()).as("enabled defaults to false").isFalse();
        assertThat(row.getCircuitState()).isEqualTo("closed");
        assertThat(row.getDomain()).as("SUPERADMIN write lands in 'default'").isEqualTo("default");
        assertThat(row.getOwnerUserId()).as("wizard modules are platform modules").isNull();
        assertThat(row.getCreatedAt()).isNotNull();
        assertThat(row.getUpdatedAt()).isNotNull();
    }

    @Test
    void upsert_wellShapedMetadata_persistsVerbatim_andReadPathParsesIt() {
        String metadata = "{\"mountAt\":\"/wizard\",\"requiresRole\":\"forum\"}";
        service.upsert(request("wizard-meta", "Wizard", "remote-shell",
                "https://wizard-meta:8443/remoteEntry.json", "./routes",
                "2.0.0", "public", true, metadata), SUPER).block();

        FederationModule row = modules.findBySlug("wizard-meta").block();
        assertThat(row).isNotNull();
        assertThat(row.getMetadata())
                .as("metadata round-trips as the raw JSON string (registry convention)")
                .isEqualTo(metadata);
        // The write is exactly what the manifest read path acts on: the SAME parser
        // the scope=role kill-switch uses extracts the declared role.
        assertThat(ManifestService.requiresRole(row.getMetadata())).isEqualTo("forum");
    }

    // ───────────────────────── upsert: refresh in place ─────────────────────────

    @Test
    void upsert_refreshesInPlace_idStable_enabledUntouchedWhenOmitted() {
        service.upsert(request("wizard-upd", "First Name", "remote-shell",
                "http://one:8080/remoteEntry.json", "./routes",
                "1.0.0", "public", true, null), SUPER).block();
        FederationModule first = modules.findBySlug("wizard-upd").block();
        Long id = first.getId();
        Instant createdAt = first.getCreatedAt();

        // Refresh: new URL/exposedModule/version, but displayName/kind/visibility/
        // enabled/metadata all OMITTED (null) — they must survive unchanged. In
        // particular enabled must STAY true (the FederationModule primitive-boolean
        // trap this DTO exists to fix).
        service.upsert(request("wizard-upd", null, null,
                "http://two:9090/remoteEntry.json", "./federated",
                "1.1.0", null, null, null), SUPER).block();

        FederationModule row = modules.findBySlug("wizard-upd").block();
        assertThat(row.getId()).as("refresh is in place — same row").isEqualTo(id);
        // This exact-equality assert doubles as the regression proof for the
        // zone-symmetric Instant WRITING converter in R2dbcConvertersConfig:
        // without it the driver encodes writes via the system zone while reads
        // assume UTC, and this save+read round-trip would shift createdAt by the
        // host's UTC offset (caught live on a UTC-7 host).
        assertThat(row.getCreatedAt()).as("createdAt never moves").isEqualTo(createdAt);
        assertThat(row.getRemoteEntryUrl()).isEqualTo("http://two:9090/remoteEntry.json");
        assertThat(row.getExposedModule()).isEqualTo("./federated");
        assertThat(row.getVersion()).isEqualTo("1.1.0");
        assertThat(row.getDisplayName()).as("omitted displayName kept").isEqualTo("First Name");
        assertThat(row.getVisibility()).as("omitted visibility kept").isEqualTo("public");
        assertThat(row.isEnabled())
                .as("an upsert body OMITTING enabled must NOT silently disable the module")
                .isTrue();
        assertThat(row.getDomain()).isEqualTo("default");
        // Exactly one row for the slug (upsert, not create-another).
        assertThat(modules.findAll().filter(m -> "wizard-upd".equals(m.getSlug()))
                .collectList().block()).hasSize(1);
    }

    @Test
    void upsert_neverClosesAnOpenCircuit_killSwitchSurvivesRePosts() {
        // A circuit-break kill (OverrideController semantics) has opened the circuit.
        service.upsert(request("wizard-killed", null, null,
                "http://killed:8080/remoteEntry.json", "./routes",
                null, "public", true, null), SUPER).block();
        FederationModule killed = modules.findBySlug("wizard-killed").block();
        killed.setCircuitState("open");
        modules.save(killed).block();

        // The wizard re-POSTs (even with enabled=true): the circuit must stay open …
        service.upsert(request("wizard-killed", "Renamed", null,
                "http://killed:8080/remoteEntry.json", "./routes",
                null, null, true, null), SUPER).block();

        FederationModule after = modules.findBySlug("wizard-killed").block();
        assertThat(after.getCircuitState())
                .as("an upsert must never lift a circuit-break kill (rearm is the only path)")
                .isEqualTo("open");
        assertThat(after.getDisplayName()).as("the rest of the refresh still lands").isEqualTo("Renamed");
        // … and the manifest render (circuit_state='closed' DB predicate) keeps
        // excluding it, even for the widest (superadmin) view.
        assertThat(renderSlugs(Set.of("ROLE_SUPERADMIN"), SUPER)).doesNotContain("wizard-killed");
    }

    // ───────────────────────── upsert: write guards (DENY) ─────────────────────────

    @Test
    void upsert_profileSlug_rejected400_andNothingPersisted() {
        // Both the general profile- vocabulary and the exact DB-reserved shape
        // (profile-<reserved>, e.g. profile-admin — the 017/032 CHECK) are 400 here.
        expect400(minimal("profile-alice"));
        expect400(minimal("profile-admin"));
        assertThat(modules.findBySlug("profile-alice").block())
                .as("a rejected upsert persists nothing").isNull();
        assertThat(modules.findBySlug("profile-admin").block()).isNull();
    }

    @Test
    void upsert_nonHttpRemoteEntryUrl_rejected400_andNothingPersisted() {
        expect400(request("wizard-ftp", null, null, "ftp://host/remoteEntry.json", "./routes",
                null, null, null, null));
        expect400(request("wizard-relative", null, null, "/remoteEntry.json", "./routes",
                null, null, null, null));
        expect400(request("wizard-hostless", null, null, "http:///remoteEntry.json", "./routes",
                null, null, null, null));
        expect400(request("wizard-garbage", null, null, "http://exa mple/x", "./routes",
                null, null, null, null));
        for (String slug : List.of("wizard-ftp", "wizard-relative", "wizard-hostless", "wizard-garbage")) {
            assertThat(modules.findBySlug(slug).block())
                    .as("a rejected upsert persists nothing (" + slug + ")").isNull();
        }
    }

    @Test
    void upsert_malformedMetadata_rejected400_andNothingPersisted() {
        String url = "http://meta:8080/remoteEntry.json";
        // Not JSON at all.
        expect400(request("wizard-badmeta", null, null, url, "./routes", null, null, null, "{nope"));
        // JSON but not an object.
        expect400(request("wizard-badmeta", null, null, url, "./routes", null, null, null, "[1,2]"));
        // mountAt present but not an absolute path.
        expect400(request("wizard-badmeta", null, null, url, "./routes", null, null, null,
                "{\"mountAt\":\"no-slash\"}"));
        // requiresRole present but not textual.
        expect400(request("wizard-badmeta", null, null, url, "./routes", null, null, null,
                "{\"requiresRole\":42}"));
        // requiresRole a ROLE_-style authority with a space — outside the bare-name shape.
        expect400(request("wizard-badmeta", null, null, url, "./routes", null, null, null,
                "{\"requiresRole\":\"has space\"}"));
        assertThat(modules.findBySlug("wizard-badmeta").block())
                .as("no metadata rejection ever persists a row").isNull();
    }

    @Test
    void upsert_rejectedRefresh_leavesExistingRowUntouched() {
        // VICTIM-CREATES-FIRST: a healthy row exists …
        service.upsert(request("wizard-victim", "Keep Me", null,
                "http://victim:8080/remoteEntry.json", "./routes",
                null, "public", true, null), SUPER).block();

        // … then a refresh with malformed metadata is rejected 400 …
        expect400(request("wizard-victim", "HIJACKED", null,
                "http://evil:8080/remoteEntry.json", "./evil",
                null, null, false, "{nope"));

        // … and (mutation-resistant) NONE of its fields changed.
        FederationModule row = modules.findBySlug("wizard-victim").block();
        assertThat(row.getDisplayName()).isEqualTo("Keep Me");
        assertThat(row.getRemoteEntryUrl()).isEqualTo("http://victim:8080/remoteEntry.json");
        assertThat(row.getExposedModule()).isEqualTo("./routes");
        assertThat(row.isEnabled()).isTrue();
    }

    // ───────────────────────── soft-disable ─────────────────────────

    @Test
    void softDisable_flipsEnabledOnly_rowStays_andManifestDropsIt() {
        service.upsert(request("wizard-live", "Live", null,
                "http://live:8080/remoteEntry.json", "./routes",
                null, "public", true, null), SUPER).block();
        // Sanity (ALLOW leg): the enabled+public row serves in the plain-user
        // default-domain manifest before the disable.
        assertThat(renderSlugs(Set.of("ROLE_USER"), PrincipalDomain.forDomain("default")))
                .contains("wizard-live");

        service.softDisable("wizard-live", SUPER).block();

        // The row STAYS (soft-disable, never a delete) with ONLY enabled flipped.
        FederationModule row = modules.findBySlug("wizard-live").block();
        assertThat(row).as("soft-disable never deletes the row").isNotNull();
        assertThat(row.isEnabled()).isFalse();
        assertThat(row.getVisibility()).as("visibility untouched").isEqualTo("public");
        assertThat(row.getCircuitState()).as("circuit untouched").isEqualTo("closed");
        assertThat(row.getDisplayName()).isEqualTo("Live");

        // MANIFEST INVARIANT: the DB-side enabled predicate now drops it for EVERY
        // caller tier — plain user AND the widest superadmin view.
        assertThat(renderSlugs(Set.of("ROLE_USER"), PrincipalDomain.forDomain("default")))
                .doesNotContain("wizard-live");
        assertThat(renderSlugs(Set.of("ROLE_SUPERADMIN"), SUPER)).doesNotContain("wizard-live");
        // … while the admin list (full registry state) still shows it.
        assertThat(service.list(SUPER).collectList().block())
                .extracting(FederationModule::getSlug).contains("wizard-live");
    }

    @Test
    void softDisable_absentSlug_is404_houseMessage() {
        StepVerifier.create(service.softDisable("wizard-nope", SUPER))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    ResponseStatusException rse = (ResponseStatusException) e;
                    assertThat(rse.getStatusCode().value()).isEqualTo(404);
                    assertThat(rse.getReason())
                            .as("exact house not-found message")
                            .isEqualTo("no module: wizard-nope");
                })
                .verify();
    }

    // ───────────────────────── list (full registry state) ─────────────────────────

    @Test
    void list_superadmin_seesEveryBrand_includingDisabledAndInternal() {
        // Rows the manifest read path hides: disabled, internal, and a foreign brand.
        modules.save(row("adm-disabled", "default", "public", false, "closed")).block();
        modules.save(row("adm-internal", "default", "internal", true, "closed")).block();
        modules.save(row("adm-brandy", "brandy", "public", true, "closed")).block();

        List<String> slugs = service.list(SUPER).collectList().block()
                .stream().map(FederationModule::getSlug).toList();
        assertThat(slugs)
                .as("the admin list is the FULL registry state — no enabled/visibility/domain cut")
                .contains("adm-disabled", "adm-internal", "adm-brandy");
    }

    // ───────────────────────── fixtures ─────────────────────────

    private List<String> renderSlugs(Set<String> authorities, PrincipalDomain scope) {
        return manifest.render(authorities, scope).block().remotes()
                .stream().map(FederationManifestDto.FederationRemoteDto::slug).toList();
    }

    private static FederationModule row(String slug, String domain, String visibility,
                                        boolean enabled, String circuit) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility(visibility);
        m.setEnabled(enabled);
        m.setCircuitState(circuit);
        m.setDomain(domain);
        return m;
    }
}
