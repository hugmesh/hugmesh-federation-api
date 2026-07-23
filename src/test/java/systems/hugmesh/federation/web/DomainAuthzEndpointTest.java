package systems.hugmesh.federation.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.model.FederationOverride;
import systems.hugmesh.federation.model.ModerationRequest;
import systems.hugmesh.federation.service.ModerationService;
import systems.hugmesh.federation.service.ModuleRegistryService;
import systems.hugmesh.federation.service.OverrideService;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * HTTP-layer ROLE authorization for the domain-scoping foundation, delineated:
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL</b> — each privileged surface ALLOWs the role it now
 *       gates on (ADMIN for modules/overrides, MOD for moderation list/submit) and
 *       the new SUPERADMIN cross-domain infra role reaches ALL of them.</li>
 *   <li><b>CROSS-USER (negative isolation)</b> — a plain ROLE_USER is DENIED (403)
 *       at every privileged surface: a user can never act as admin/mod/superadmin.</li>
 * </ul>
 *
 * <p>Runs the real SecurityConfig chain under the {@code test} profile with the
 * write services mocked, so the assertion is the AUTHZ outcome (200/403), not the
 * service behaviour. Mirrors {@code ValidationEndpointTest}'s context wiring.
 */
@SpringBootTest
@ActiveProfiles("test")
class DomainAuthzEndpointTest extends PostgresTestSupport {

    // Spring Security 7: the mockJwt()/mockOpaqueToken() reactive mutators stash the
    // SecurityContext in an exchange attribute that is ONLY picked up by the MutatorFilter
    // the springSecurity() configurer installs. A WebTestClient autowired via
    // @AutoConfigureWebTestClient does NOT have that configurer, so the mutator's auth is
    // silently dropped and every request runs anonymous -> 401. Build the client from the
    // ApplicationContext with .apply(springSecurity()) so the mutator is honoured.
    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean ModuleRegistryService registry;
    @MockitoBean ModerationService moderation;
    @MockitoBean OverrideService overrides;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient as(String role) {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_" + role)));
    }

    private void stubReads() {
        when(registry.list(any())).thenReturn(Flux.just(new FederationModule()));
        when(overrides.list(any())).thenReturn(Flux.just(new FederationOverride()));
        when(moderation.list(any())).thenReturn(Flux.just(new ModerationRequest()));
    }

    // ── USER-SITUATIONAL ALLOW: each role reaches the surface it gates ──

    @Test
    void admin_listsModules_200() {
        stubReads();
        as("ADMIN").get().uri("/api/federation/modules").exchange().expectStatus().isOk();
    }

    @Test
    void admin_listsOverrides_200() {
        stubReads();
        as("ADMIN").get().uri("/api/federation/overrides").exchange().expectStatus().isOk();
    }

    @Test
    void mod_listsModeration_200() {
        stubReads();
        as("MOD").get().uri("/api/federation/moderation").exchange().expectStatus().isOk();
    }

    // ── recommend-instance-block: the narrower MATRIX/MASTODON self-service path ──
    // (root-cause fix — see SecurityConfig / ModerationController javadoc: this used
    // to be the ONLY route user-bff-api's recommend-instance-block feature had, and
    // the mod-only submit surface's gate made it end-to-end unreachable.)

    @Test
    void matrix_recommendsInstanceBlock_200() {
        when(moderation.submit(any(), any(), any(), any(), any())).thenReturn(Mono.just(new ModerationRequest()));
        as("MATRIX").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void mastodon_recommendsInstanceBlock_200() {
        when(moderation.submit(any(), any(), any(), any(), any())).thenReturn(Mono.just(new ModerationRequest()));
        as("MASTODON").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void matrix_recommendInstanceBlock_kindIsHardcoded_neverCallerSupplied() {
        // FAIL-CLOSED: even if a malicious/confused caller sneaks a "kind" field into
        // the body, RecommendInstanceBlockRequest has no kind field to bind it to —
        // the controller always calls submit(..., "instance-block", ...). Prove the
        // service is invoked with the literal "instance-block" kind regardless.
        when(moderation.submit(any(), any(), any(), any(), any())).thenReturn(Mono.just(new ModerationRequest()));
        as("MATRIX").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\",\"reason\":\"spam\",\"kind\":\"user-removal\"}")
                .exchange()
                .expectStatus().isOk();
        org.mockito.Mockito.verify(moderation).submit(any(), org.mockito.ArgumentMatchers.eq("instance-block"),
                org.mockito.ArgumentMatchers.eq("evil.example"), any(), any());
    }

    @Test
    void user_isDeniedRecommendInstanceBlock_403() {
        // A plain USER (no platform role) never reaches even this narrower surface.
        as("USER").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void mod_isDeniedRecommendInstanceBlock_403_gateIsExactlyMatrixMastodon() {
        // FAIL-CLOSED: a MOD (who freely reaches the general moderation surface) does
        // NOT get an extra route in via this narrower, platform-participant-only path.
        as("MOD").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void admin_isDeniedRecommendInstanceBlock_403_gateIsExactlyMatrixMastodon() {
        as("ADMIN").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void superadmin_isDeniedRecommendInstanceBlock_403_noHierarchyEdgeToPlatformRoles() {
        // SUPERADMIN's RoleHierarchy edges only reach ADMIN/MOD/USER — NOT
        // MATRIX/MASTODON (those are platform-participation flags, not a privilege
        // tier) — so even the cross-domain infra role does not get an extra route in
        // here. SUPERADMIN already has the general submit surface for this purpose.
        as("SUPERADMIN").post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    // ── SUPERADMIN: the cross-domain infra role reaches every privileged surface ──

    @Test
    void superadmin_listsModules_200() {
        stubReads();
        as("SUPERADMIN").get().uri("/api/federation/modules").exchange().expectStatus().isOk();
    }

    @Test
    void superadmin_listsOverrides_200() {
        stubReads();
        as("SUPERADMIN").get().uri("/api/federation/overrides").exchange().expectStatus().isOk();
    }

    @Test
    void superadmin_listsModeration_200() {
        stubReads();
        as("SUPERADMIN").get().uri("/api/federation/moderation").exchange().expectStatus().isOk();
    }

    // ── CROSS-USER negative isolation: a plain USER is DENIED everywhere privileged ──

    @Test
    void user_isDeniedModules_403() {
        as("USER").get().uri("/api/federation/modules").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_isDeniedOverrides_403() {
        as("USER").get().uri("/api/federation/overrides").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_isDeniedModeration_403() {
        as("USER").get().uri("/api/federation/moderation").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_isDeniedUsernameOracle_403() {
        // The username availability oracle is SERVICE/ADMIN/SUPERADMIN — never a user.
        as("USER").get().uri("/api/federation/username/alice/availability")
                .exchange().expectStatus().isForbidden();
    }

    // ── PUBLIC projections stay reachable (UNCHANGED) ──

    @Test
    void capabilities_isPublic_evenAnonymous_200() {
        web.get().uri("/api/federation/capabilities").exchange().expectStatus().isOk();
    }
}
