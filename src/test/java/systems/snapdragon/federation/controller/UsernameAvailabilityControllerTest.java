package systems.snapdragon.federation.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.UsernameAvailabilityDto;
import systems.snapdragon.federation.service.UsernameAvailabilityService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * SECURITY / gating coverage for the username availability endpoint over the real
 * HTTP layer. The whole {@code /api/federation/username/**} controller is an
 * ENUMERATION ORACLE ({@code matchedWith} names the colliding username / reserved
 * label), so it MUST be INTERNAL — {@code ROLE_SERVICE} (or {@code ROLE_ADMIN}),
 * never a public / plain-authenticated / ROLE_USER surface.
 *
 * <p>Runs the full app context under the {@code test} profile (the real
 * {@link systems.snapdragon.federation.config.SecurityConfig} chain) with the
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
@AutoConfigureWebTestClient
@ActiveProfiles("test")
// A distinct @SpringBootTest context (adds @MockitoBean) -> give it its OWN H2 mem
// DB so its Liquibase run never collides with the shared slice store.
@TestPropertySource(properties = {
        "spring.r2dbc.url=r2dbc:h2:mem:///fed_username_ctx;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=",
        "spring.liquibase.url=jdbc:h2:mem:fed_username_ctx;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION;DATABASE_TO_LOWER=TRUE"
})
class UsernameAvailabilityControllerTest {

    private static final String AVAIL = "/api/federation/username/charlie/availability";
    private static final String CONFUSABLES = "/api/federation/username/charlie/confusables";

    @Autowired WebTestClient web;

    @MockitoBean UsernameAvailabilityService availability;

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
