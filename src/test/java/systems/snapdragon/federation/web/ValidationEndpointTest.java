package systems.snapdragon.federation.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.service.ModerationService;
import systems.snapdragon.federation.service.ModuleRegistryService;
import systems.snapdragon.federation.service.OverrideService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

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
@AutoConfigureWebTestClient
@ActiveProfiles("test")
// This is a SECOND @SpringBootTest context (it adds @MockitoBean services), so it
// gets its OWN H2 mem DB rather than sharing application-test.yml's `fed_ctx` —
// otherwise the two contexts' Liquibase runs collide on the shared store
// ("DATABASECHANGELOG already exists") and rows leak across the slice tests.
@TestPropertySource(properties = {
        "spring.r2dbc.url=r2dbc:h2:mem:///fed_validation_ctx;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=",
        "spring.liquibase.url=jdbc:h2:mem:fed_validation_ctx;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION;DATABASE_TO_LOWER=TRUE"
})
class ValidationEndpointTest {

    @Autowired WebTestClient web;

    @MockitoBean ModuleRegistryService registry;
    @MockitoBean ModerationService moderation;
    @MockitoBean OverrideService overrides;

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
