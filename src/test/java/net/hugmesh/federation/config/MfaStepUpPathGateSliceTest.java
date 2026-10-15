package net.hugmesh.federation.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResolvers;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.Roles;
import net.hugmesh.federation.testsupport.TestIssuer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The D8 STEP-UP path gate: {@code SecurityConfig.stepUp} wrapping the mutating verbs
 * of {@code /api/federation/admin/modules/**} and {@code POST .../moderation/{id}/decide}.
 * Same slice plumbing as {@link AdminModulePathGateSliceTest} (real RS256 tokens from
 * in-process issuers, the production filter chain), driven once with
 * {@code app.mfa.enabled=false} and once with {@code true} against the SAME policy code.
 *
 * <p>Two properties are pinned. DARK = no-op: with the flag off the converter never
 * emits the marker, so an unconditional check would 403 every superadmin and admin.
 * FLIPPED = enforced: the guarded writes demand {@link Roles#MFA_SATISFIED}, which the
 * converter derives only from a FRESH {@code mfa_satisfied_at} claim.
 */
class MfaStepUpPathGateSliceTest extends SecuritySliceSupport {

    private static final long WINDOW_MILLIS = 600_000L;

    private static final String MODULES = "/api/federation/admin/modules";
    private static final String MODULE_ITEM = "/api/federation/admin/modules/some-slug";
    private static final String DECIDE = "/api/federation/moderation/11111111-1111-1111-1111-111111111111/decide";
    private static final String REFER = "/api/federation/moderation/11111111-1111-1111-1111-111111111111/refer";

    /** Maps every verb on the probed paths so an ALLOWED request is a 200 rather than a
     *  404 that could hide a missing security decision. */
    @RestController
    static class Stub {
        @RequestMapping({MODULES, MODULE_ITEM, DECIDE, REFER})
        Mono<String> ok() { return Mono.just("ok"); }
    }

    private TestIssuer issuer;
    private TestIssuer issuer2;
    private WebTestClient mfaOff;
    private WebTestClient mfaOn;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(),
                issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy");
        mfaOff = sliceClient(registry, provider(resolver(registry, false)), new Stub());
        mfaOn = mfaSliceClient(registry, provider(resolver(registry, true)), new Stub());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private static ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver(
            DomainRegistry registry, boolean mfaEnabled) {
        return TenancyResolvers.tenantResolver(new TenancyResourceServerConfig(
                registry, "", "", mfaEnabled, WINDOW_MILLIS));
    }

    private String token(List<String> roles, Map<String, Object> extra) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("roles", roles.stream().map(r -> Map.of("name", r)).toList());
        claims.put("name", "u");
        claims.putAll(extra);
        return issuer.mintWithClaims("u", claims);
    }

    private String plain(String... roles) {
        return token(List.of(roles), Map.of());
    }

    private String steppedUp(long ageMillis, String... roles) {
        return token(List.of(roles), Map.of(Roles.MFA_SATISFIED_AT_CLAIM,
                String.valueOf(System.currentTimeMillis() - ageMillis)));
    }

    private static WebTestClient.ResponseSpec call(
            WebTestClient c, HttpMethod m, String path, String bearer) {
        return c.method(m).uri(path).headers(h -> h.setBearerAuth(bearer)).exchange();
    }

    // --- flag OFF: byte-identical to today ------------------------------------

    @Test
    void mfaDisabled_moduleWrites_superadminWithoutStamp_allowed() {
        for (HttpMethod m : List.of(HttpMethod.POST, HttpMethod.DELETE)) {
            call(mfaOff, m, MODULE_ITEM, plain("superadmin")).expectStatus().isOk();
        }
    }

    @Test
    void mfaDisabled_moduleWrites_admin_stillForbidden() {
        call(mfaOff, HttpMethod.POST, MODULES, plain("admin")).expectStatus().isForbidden();
    }

    @Test
    void mfaDisabled_decide_adminAndModWithoutStamp_stillReachTheMethodGate() {
        // The path gate is the unchanged MOD/ADMIN/SUPERADMIN rule (the method-level
        // @PreAuthorize narrows MOD out later), so all three pass here with no stamp.
        call(mfaOff, HttpMethod.POST, DECIDE, plain("admin")).expectStatus().isOk();
        call(mfaOff, HttpMethod.POST, DECIDE, plain("mod")).expectStatus().isOk();
        call(mfaOff, HttpMethod.POST, DECIDE, plain("superadmin")).expectStatus().isOk();
    }

    // --- flag ON: module writes ------------------------------------------------

    @Test
    void mfaEnabled_moduleWrites_withoutStamp_forbidden() {
        for (HttpMethod m : List.of(
                HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)) {
            call(mfaOn, m, MODULE_ITEM, plain("superadmin")).expectStatus().isForbidden();
        }
        call(mfaOn, HttpMethod.POST, MODULES, plain("superadmin")).expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moduleWrites_freshStamp_allowed() {
        call(mfaOn, HttpMethod.POST, MODULES, steppedUp(1_000L, "superadmin")).expectStatus().isOk();
        call(mfaOn, HttpMethod.DELETE, MODULE_ITEM, steppedUp(1_000L, "superadmin")).expectStatus().isOk();
    }

    @Test
    void mfaEnabled_moduleWrites_staleStamp_forbidden() {
        call(mfaOn, HttpMethod.POST, MODULES, steppedUp(WINDOW_MILLIS + 60_000L, "superadmin"))
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moduleWrites_futureStamp_forbidden() {
        call(mfaOn, HttpMethod.POST, MODULES, steppedUp(-60_000L, "superadmin"))
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moduleWrites_forgedPermissionMarker_forbidden() {
        String forged = token(List.of("superadmin"), Map.of("permissions", List.of(Roles.MFA_SATISFIED)));
        call(mfaOn, HttpMethod.POST, MODULES, forged).expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moduleWrites_stepUpDoesNotReplaceTheRole() {
        call(mfaOn, HttpMethod.POST, MODULES, steppedUp(1_000L, "admin")).expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_moduleWrites_anonymous_stillUnauthorized() {
        mfaOn.post().uri(MODULES).exchange().expectStatus().isUnauthorized();
    }

    @Test
    void mfaEnabled_moduleReads_notStepUpGated() {
        call(mfaOn, HttpMethod.GET, MODULES, plain("superadmin")).expectStatus().isOk();
    }

    // --- flag ON: moderation decide -------------------------------------------

    @Test
    void mfaEnabled_decide_withoutStamp_forbidden() {
        call(mfaOn, HttpMethod.POST, DECIDE, plain("admin")).expectStatus().isForbidden();
        call(mfaOn, HttpMethod.POST, DECIDE, plain("superadmin")).expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_decide_freshStamp_allowed() {
        call(mfaOn, HttpMethod.POST, DECIDE, steppedUp(1_000L, "admin")).expectStatus().isOk();
    }

    @Test
    void mfaEnabled_decide_staleStamp_forbidden() {
        call(mfaOn, HttpMethod.POST, DECIDE, steppedUp(WINDOW_MILLIS + 60_000L, "admin"))
                .expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_decide_stepUpDoesNotReplaceTheRole() {
        call(mfaOn, HttpMethod.POST, DECIDE, steppedUp(1_000L, "user")).expectStatus().isForbidden();
    }

    @Test
    void mfaEnabled_decide_anonymous_stillUnauthorized() {
        mfaOn.post().uri(DECIDE).exchange().expectStatus().isUnauthorized();
    }

    @Test
    void mfaEnabled_otherModerationRoutes_notStepUpGated() {
        // Only the decision is in this slice: refer stays on the plain MOD/ADMIN/SUPERADMIN rule.
        call(mfaOn, HttpMethod.POST, REFER, plain("mod")).expectStatus().isOk();
    }
}
