package systems.hugmesh.federation.controller;

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
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.federation.model.ResolvedFindingView;
import systems.hugmesh.federation.service.SystemFindingService;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * SECURITY / gating + domain-scope coverage for the resolved-findings RECONCILE read
 * ({@code GET /api/federation/findings/resolved}) over the real HTTP layer. This is an
 * INTERNAL service-to-service endpoint the admin-bff moderation → activation reconciler
 * polls, gated to {@code ROLE_SERVICE} (the reconciler's token) / {@code ROLE_ADMIN} /
 * {@code ROLE_SUPERADMIN}, mirroring the {@code /api/federation/username/**} convention —
 * NEVER a public / ROLE_USER / ROLE_MOD surface (a per-domain MOD lists+resolves via the
 * bare path, but does not drive the cross-domain reconcile read).
 *
 * <p>Runs the full app context under the {@code test} profile (the real
 * {@link systems.hugmesh.federation.config.SecurityConfig} chain) with the service
 * mocked, so the assertion is the AUTH outcome (401 / 403 / 2xx) + the cross-domain
 * decision threaded to the service, not a DB result. Asserts:
 * <ul>
 *   <li>anonymous → 401;</li>
 *   <li>{@code ROLE_USER} → 403 (not a public surface);</li>
 *   <li>{@code ROLE_MOD} → 403 (mod drives list/resolve, not the reconcile read);</li>
 *   <li>{@code ROLE_SERVICE} → 2xx + crossDomain=true (the platform reconciler);</li>
 *   <li>{@code ROLE_ADMIN} → 2xx + crossDomain=false (per-domain reconciler — own brand);</li>
 *   <li>{@code ROLE_SUPERADMIN} → 2xx + crossDomain=true (cross-domain infra role);</li>
 *   <li>missing {@code surface} → 400 (the service is never called).</li>
 * </ul>
 */
@SpringBootTest
@ActiveProfiles("test")
class SystemFindingResolvedEndpointTest extends PostgresTestSupport {

    private static final String RESOLVED = "/api/federation/findings/resolved";

    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean SystemFindingService findings;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient as(String role) {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_" + role)));
    }

    private void stubOneRow() {
        when(findings.resolvedForReconcile(any(), anyLong(), anyInt(), anyBoolean(), any()))
                .thenReturn(Flux.just(new ResolvedFindingView(
                        7L, "character-part", "part-42", "actioned", "mod-bob", "default", Instant.now())));
    }

    // ── the gate: anonymous + ROLE_USER + ROLE_MOD are refused ────────────────────

    @Test
    void resolved_anonymous_is401() {
        web.get().uri(RESOLVED + "?surface=character-part").exchange().expectStatus().isUnauthorized();
        verify(findings, never()).resolvedForReconcile(any(), anyLong(), anyInt(), anyBoolean(), any());
    }

    @Test
    void resolved_roleUser_is403() {
        as("USER").get().uri(RESOLVED + "?surface=character-part").exchange().expectStatus().isForbidden();
        verify(findings, never()).resolvedForReconcile(any(), anyLong(), anyInt(), anyBoolean(), any());
    }

    @Test
    void resolved_roleMod_is403_notTheReconcileReader() {
        // A per-domain MOD lists+resolves via the bare path, but the cross-domain reconcile
        // read is SERVICE/ADMIN/SUPERADMIN only.
        as("MOD").get().uri(RESOLVED + "?surface=character-part").exchange().expectStatus().isForbidden();
        verify(findings, never()).resolvedForReconcile(any(), anyLong(), anyInt(), anyBoolean(), any());
    }

    // ── SERVICE / ADMIN / SUPERADMIN pass; crossDomain is threaded per role ────────

    @Test
    void resolved_roleService_is2xx_crossDomainTrue() {
        stubOneRow();
        as("SERVICE").get().uri(RESOLVED + "?surface=character-part&sinceId=5&limit=50").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].id").isEqualTo(7)
                .jsonPath("$[0].surface").isEqualTo("character-part")
                .jsonPath("$[0].subjectRef").isEqualTo("part-42")
                .jsonPath("$[0].status").isEqualTo("actioned")
                .jsonPath("$[0].reviewer").isEqualTo("mod-bob")
                .jsonPath("$[0].domain").isEqualTo("default");
        // The platform reconciler (SERVICE token) reads CROSS-DOMAIN.
        verify(findings).resolvedForReconcile(eq("character-part"), eq(5L), eq(50), eq(true), any(PrincipalDomain.class));
    }

    @Test
    void resolved_roleAdmin_is2xx_crossDomainFalse_perDomain() {
        stubOneRow();
        as("ADMIN").get().uri(RESOLVED + "?surface=character-part").exchange().expectStatus().isOk();
        // A per-domain ADMIN reconciler is pinned to its own brand → crossDomain=false,
        // sinceId defaults 0, limit defaults 0 (service clamps to the default page size).
        verify(findings).resolvedForReconcile(eq("character-part"), eq(0L), eq(0), eq(false), any(PrincipalDomain.class));
    }

    @Test
    void resolved_roleSuperadmin_is2xx_crossDomainTrue() {
        stubOneRow();
        as("SUPERADMIN").get().uri(RESOLVED + "?surface=character-sticker").exchange().expectStatus().isOk();
        // SUPERADMIN is the cross-domain infra role → crossDomain=true.
        verify(findings).resolvedForReconcile(eq("character-sticker"), eq(0L), eq(0), eq(true), any(PrincipalDomain.class));
    }

    // ── validation: a missing surface is a 400 and never reaches the service ───────

    @Test
    void resolved_missingSurface_is400() {
        as("SERVICE").get().uri(RESOLVED).exchange().expectStatus().isBadRequest();
        verify(findings, never()).resolvedForReconcile(any(), anyLong(), anyInt(), anyBoolean(), any());
    }
}
