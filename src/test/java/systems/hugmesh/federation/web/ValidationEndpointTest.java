package systems.hugmesh.federation.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.model.FederationOverride;
import systems.hugmesh.federation.model.ModerationRequest;
import systems.hugmesh.federation.service.ModerationService;
import systems.hugmesh.federation.service.ModuleRegistryService;
import systems.hugmesh.federation.service.OverrideService;
import net.hugmesh.commons.testsupport.PostgresTestSupport;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * END-TO-END validation coverage over the HTTP layer (the only layer where jakarta
 * Bean Validation + the reactive {@link ValidationExceptionHandler} actually fire):
 * a request that VIOLATES each newly-added constraint must come back as a clean
 * {@code 400} whose body names the offending field, AND the service must NOT be
 * invoked (validation short-circuits before the controller body). A VALID request
 * is accepted (the constraint never rejects good input — existing behavior intact).
 *
 * <p>Runs the full app context under the {@code test} profile (the real
 * SecurityConfig chain) with the write services mocked, authenticating with a
 * {@code mockJwt()} carrying the role each route requires — so the assertion is the
 * VALIDATION outcome, not an auth 401/403.
 */
@SpringBootTest
@ActiveProfiles("test")
// A distinct @SpringBootTest context (it adds @MockitoBean services), so it gets its
// OWN Postgres container via PostgresTestSupport — fully isolated Liquibase run.
class ValidationEndpointTest extends PostgresTestSupport {

    // Spring Security 7: the mockJwt() reactive mutator only injects the SecurityContext
    // when the springSecurity() configurer's MutatorFilter is in the chain. An
    // @AutoConfigureWebTestClient-autowired client lacks it (mutator dropped -> 401), so
    // build the client from the ApplicationContext with .apply(springSecurity()).
    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean ModuleRegistryService registry;
    @MockitoBean ModerationService moderation;
    @MockitoBean OverrideService overrides;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient admin() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private WebTestClient mod() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_MOD")));
    }

    // ------------------------------------------------------------------
    // Module registry — @Valid(OnCreate) body + slug path-variable pattern
    // ------------------------------------------------------------------

    @Test
    void createModule_missingRequiredFields_is400_withFieldErrors_andNeverCallsService() {
        admin().post().uri("/api/federation/modules")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")   // no slug / displayName / kind / remoteEntryUrl / version
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.slug").exists()
                .jsonPath("$.fields.kind").exists()
                .jsonPath("$.fields.version").exists();
        verify(registry, never()).create(any(), any());
    }

    @Test
    void createModule_badKindEnum_is400() {
        admin().post().uri("/api/federation/modules")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"slug\":\"ok-slug\",\"displayName\":\"D\",\"kind\":\"BOGUS\","
                        + "\"remoteEntryUrl\":\"/r\",\"version\":\"1\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.kind").exists();
        verify(registry, never()).create(any(), any());
    }

    @Test
    void createModule_valid_is2xx_callsService() {
        FederationModule saved = new FederationModule();
        saved.setSlug("ok-slug");
        when(registry.create(any(), any())).thenReturn(Mono.just(saved));
        admin().post().uri("/api/federation/modules")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"slug\":\"ok-slug\",\"displayName\":\"D\",\"kind\":\"fragment\","
                        + "\"remoteEntryUrl\":\"/r\",\"version\":\"1\",\"visibility\":\"public\"}")
                .exchange()
                .expectStatus().isCreated();
        verify(registry).create(any(), any());
    }

    @Test
    void getModule_badSlug_is400_pathVariablePattern() {
        admin().get().uri("/api/federation/modules/Bad_Slug!")
                .exchange()
                .expectStatus().isBadRequest();
        verify(registry, never()).get(anyString(), any());
    }

    // ------------------------------------------------------------------
    // Moderation — @Valid SubmitRequest + status param pattern
    // ------------------------------------------------------------------

    @Test
    void submitModeration_badKind_is400() {
        mod().post().uri("/api/federation/moderation")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"nope\",\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.kind").exists();
        verify(moderation, never()).submit(any(), any(), any(), any(), any());
    }

    @Test
    void submitModeration_missingTarget_is400() {
        mod().post().uri("/api/federation/moderation")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.target").exists();
        verify(moderation, never()).submit(any(), any(), any(), any(), any());
    }

    @Test
    void listModeration_badStatusParam_is400() {
        mod().get().uri("/api/federation/moderation?status=bogus")
                .exchange()
                .expectStatus().isBadRequest();
        verify(moderation, never()).listByStatus(anyString(), any());
    }

    @Test
    void submitModeration_valid_is2xx() {
        when(moderation.submit(any(), any(), any(), any(), any())).thenReturn(Mono.just(new ModerationRequest()));
        mod().post().uri("/api/federation/moderation")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\",\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange()
                .expectStatus().is2xxSuccessful();
        verify(moderation).submit(any(), any(), any(), any(), any());
    }

    // ------------------------------------------------------------------
    // Override — @Valid ApplyRequest scope/action enums + ClearScopeRequest
    // ------------------------------------------------------------------

    @Test
    void applyOverride_badScopeAndAction_is400() {
        admin().post().uri("/api/federation/overrides")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"moduleSlug\":\"a-mod\",\"scope\":\"galaxy\",\"action\":\"nuke\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.fields.scope").exists()
                .jsonPath("$.fields.action").exists();
        verify(overrides, never()).apply(any(), any(), any(), any(), any(), any());
    }

    @Test
    void applyOverride_valid_is2xx() {
        when(overrides.apply(any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new FederationOverride()));
        admin().post().uri("/api/federation/overrides")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"moduleSlug\":\"a-mod\",\"scope\":\"user\",\"scopeValue\":\"u1\","
                        + "\"action\":\"circuit-break\"}")
                .exchange()
                .expectStatus().is2xxSuccessful();
        verify(overrides).apply(any(), any(), any(), any(), any(), any());
    }

    @Test
    void clearScope_badScope_is400() {
        admin().post().uri("/api/federation/overrides/clear")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"scope\":\"everything\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.scope").exists();
        verify(overrides, never()).clearScope(any(), any(), any());
    }
}
