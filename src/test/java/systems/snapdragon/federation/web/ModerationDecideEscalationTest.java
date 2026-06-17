package systems.snapdragon.federation.web;

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
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.service.ModerationService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * The MODERATION ESCALATION BOUNDARY at HTTP — {@code POST
 * /api/federation/moderation/{id}/decide}. This is the federation-api-specific gap
 * the coarse path-gate slice canNOT cover: the path rule for
 * {@code /api/federation/moderation/**} is {@code hasAnyRole('MOD','ADMIN','SUPERADMIN')}
 * (a MOD PASSES it), but the {@code decide} method is narrowed by
 * {@code @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")} — METHOD security, which
 * needs the {@code @EnableReactiveMethodSecurity} AOP proxy from a real context, so
 * the lightweight {@code SecuritySliceSupport} slice does not activate it.
 *
 * <p>Runs the real chain + method security under the {@code test} profile with the
 * write service mocked (mirrors {@code DomainAuthzEndpointTest}'s context wiring), so
 * the assertion is the AUTHZ outcome (403 vs 200), not the service behaviour.
 *
 * <p>Delineated:
 * <ul>
 *   <li><b>CROSS-USER DENY (escalation boundary)</b> — a {@code ROLE_MOD} that
 *       cleared the coarse path gate is DENIED 403 by {@code @PreAuthorize} on
 *       {@code decide}, and the service is NEVER invoked (no decision leaks).</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — {@code ROLE_ADMIN} and the cross-domain
 *       {@code ROLE_SUPERADMIN} reach {@code decide} (200) and invoke the service.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "spring.r2dbc.url=r2dbc:h2:mem:///fed_decide_ctx;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=",
        "spring.liquibase.url=jdbc:h2:mem:fed_decide_ctx;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION;DATABASE_TO_LOWER=TRUE"
})
class ModerationDecideEscalationTest {

    private static final String DECIDE = "/api/federation/moderation/7/decide?approve=true";

    @Autowired WebTestClient web;

    @MockitoBean ModerationService moderation;

    private WebTestClient as(String role) {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_" + role)));
    }

    // ── CROSS-USER DENY: a MOD clears the path gate but @PreAuthorize denies decide ──

    @Test
    void mod_isDeniedDecide_403_andServiceNeverInvoked() {
        as("MOD").post().uri(DECIDE).exchange().expectStatus().isForbidden();
        // The decision must never have been attempted — the escalation is blocked
        // BEFORE the service, so no approve/deny side effect can leak.
        verify(moderation, never()).decide(any(), anyBoolean(), anyString(), any());
    }

    // ── USER-SITUATIONAL ALLOW: ADMIN / SUPERADMIN reach decide ──

    @Test
    void admin_canDecide_200() {
        when(moderation.decide(eq(7L), eq(true), anyString(), any()))
                .thenReturn(Mono.just(new ModerationRequest()));
        as("ADMIN").post().uri(DECIDE).exchange().expectStatus().isOk();
        verify(moderation).decide(eq(7L), eq(true), anyString(), any());
    }

    @Test
    void superadmin_canDecide_200() {
        when(moderation.decide(eq(7L), eq(true), anyString(), any()))
                .thenReturn(Mono.just(new ModerationRequest()));
        as("SUPERADMIN").post().uri(DECIDE).exchange().expectStatus().isOk();
        verify(moderation).decide(eq(7L), eq(true), anyString(), any());
    }
}
