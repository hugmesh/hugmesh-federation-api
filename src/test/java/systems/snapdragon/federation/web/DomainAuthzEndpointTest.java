package systems.snapdragon.federation.web;

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
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.service.ModerationService;
import systems.snapdragon.federation.service.ModuleRegistryService;
import systems.snapdragon.federation.service.OverrideService;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;

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
