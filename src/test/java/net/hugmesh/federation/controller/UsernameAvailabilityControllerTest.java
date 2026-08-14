package net.hugmesh.federation.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.model.UsernameAvailabilityDto;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.federation.service.UsernameAvailabilityService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * SECURITY / gating coverage for the username availability endpoint over the real
 * HTTP layer. The whole {@code /api/federation/username/**} controller is an
 * ENUMERATION ORACLE ({@code matchedWith} names the colliding username / reserved
 * label), so it MUST be INTERNAL — {@code ROLE_SERVICE} (or {@code ROLE_ADMIN}),
 * never a public / plain-authenticated / ROLE_USER surface.
 *
 * <p>Runs the full app context under the {@code test} profile (the real
 * {@link net.hugmesh.federation.config.SecurityConfig} chain) with the
 * availability service mocked, so the assertion is the AUTH outcome (401 / 403 /
 * 2xx), not a business result. Asserts:
 * <ul>
 *   <li>anonymous -> 401;</li>
 *   <li>{@code ROLE_USER} -> 403 (NOT public — a normal logged-in user can't
 *       enumerate);</li>
 *   <li>{@code ROLE_SERVICE} -> 2xx (the internal mint-path credential);</li>
 *   <li>{@code ROLE_ADMIN} -> 2xx;</li>
 *   <li>the ADMIN-only {@code /confusables} debug rejects a {@code ROLE_SERVICE}
 *       caller with 403 (method security narrows it);</li>
 *   <li>{@code override=confusable} is ignored for a non-admin (ROLE_SERVICE) caller
 *       — the un-overridden verdict comes back.</li>
 * </ul>
 */
@SpringBootTest
@ActiveProfiles("test")
// A distinct @SpringBootTest context (adds @MockitoBean) -> PostgresTestSupport gives
// it its OWN Postgres container so its Liquibase run is isolated from the others.
class UsernameAvailabilityControllerTest extends PostgresTestSupport {

    private static final String AVAIL = "/api/federation/username/charlie/availability";
    private static final String CONFUSABLES = "/api/federation/username/charlie/confusables";

    // Spring Security 7: mockJwt()'s SecurityContext is only honoured when the
    // springSecurity() configurer's MutatorFilter is in the chain; an
    // @AutoConfigureWebTestClient-autowired client lacks it (mutator dropped -> 401).
    // Build from the ApplicationContext with .apply(springSecurity()). The anonymous
    // legs (no mutator) still resolve to 401 exactly as before.
    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean UsernameAvailabilityService availability;

    @BeforeEach
    void setUpClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient as(String role) {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_" + role)));
    }

    private void stubAvailable() {
        when(availability.check(any(), any()))
                .thenReturn(Mono.just(UsernameAvailabilityDto.available("charlie", "chariie")));
    }

    // ── the gate: anonymous + ROLE_USER are refused; SERVICE + ADMIN pass ─────────

    @Test
    void availability_anonymous_is401() {
        web.get().uri(AVAIL).exchange().expectStatus().isUnauthorized();
        verify(availability, never()).check(any(), any());
    }

    @Test
    void availability_roleUser_is403_notPublic() {
        // A normal logged-in user is NOT allowed to enumerate the namespace.
        as("USER").get().uri(AVAIL).exchange().expectStatus().isForbidden();
        verify(availability, never()).check(any(), any());
    }

    @Test
    void availability_roleService_is2xx_andCallsService() {
        stubAvailable();
        as("SERVICE").get().uri(AVAIL).exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.available").isEqualTo(true)
                .jsonPath("$.skeleton").isEqualTo("chariie");
        verify(availability).check(eq("charlie"), isNull());
    }

    @Test
    void availability_roleAdmin_is2xx() {
        stubAvailable();
        as("ADMIN").get().uri(AVAIL).exchange().expectStatus().isOk();
        verify(availability).check(eq("charlie"), isNull());
    }

    @Test
    void availability_roleSuperadmin_is2xx() {
        // SUPERADMIN > ADMIN: the cross-domain infra role must reach the username oracle.
        // Regression guard for the SUPERADMIN-lockout fix — before the RoleHierarchy bean
        // was wired into method security, the @PreAuthorize narrowing to ADMIN wrongly
        // 403'd SUPERADMIN (the path rule admitted it but the method gate did not).
        stubAvailable();
        as("SUPERADMIN").get().uri(AVAIL).exchange().expectStatus().isOk();
        verify(availability).check(eq("charlie"), isNull());
    }

    // ── POST /check is gated identically ─────────────────────────────────────────

    @Test
    void postCheck_roleUser_is403() {
        as("USER").post().uri("/api/federation/username/check")
                .bodyValue("{\"candidate\":\"charlie\"}")
                .exchange().expectStatus().isForbidden();
        verify(availability, never()).check(any(), any());
    }

    // ── /confusables debug is ADMIN-only (method security narrows it) ─────────────

    @Test
    void confusables_roleService_is403_adminOnly() {
        // ROLE_SERVICE clears the path gate but NOT the @PreAuthorize("hasRole('ADMIN')").
        as("SERVICE").get().uri(CONFUSABLES).exchange().expectStatus().isForbidden();
        verify(availability, never()).check(any(), any());
    }

    @Test
    void confusables_roleAdmin_is2xx() {
        stubAvailable();
        as("ADMIN").get().uri(CONFUSABLES).exchange().expectStatus().isOk();
        verify(availability).check(eq("charlie"), isNull());
    }

    @Test
    void confusables_roleSuperadmin_is2xx() {
        // hasRole('ADMIN') on /confusables must admit SUPERADMIN via the RoleHierarchy.
        stubAvailable();
        as("SUPERADMIN").get().uri(CONFUSABLES).exchange().expectStatus().isOk();
        verify(availability).check(eq("charlie"), isNull());
    }

    // ── override=confusable is ADMIN-only: a SERVICE caller's override is ignored ──

    @Test
    void override_confusable_isIgnoredForNonAdminServiceCaller() {
        // The check returns an EXACT collision; a ROLE_SERVICE caller asks to override
        // it, but the override is ADMIN-only -> the un-overridden (collide) verdict
        // is returned unchanged (the override is silently ignored, never leaks 403).
        when(availability.check(any(), any()))
                .thenReturn(Mono.just(UsernameAvailabilityDto.collide("charlie", "exact", "charley", "chariie")));

        as("SERVICE").get().uri(AVAIL + "?override=confusable").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.available").isEqualTo(false)
                .jsonPath("$.reason").isEqualTo("exact");
    }
}
