package systems.snapdragon.federation.web;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.repository.ModerationRequestRepository;
import systems.snapdragon.commons.testsupport.PostgresTestSupport;
import systems.snapdragon.federation.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * HTTP-boundary authz + behaviour for {@code POST
 * /api/federation/moderation/recommend-instance-block}, end-to-end through the REAL
 * production filter chain in genuine multi-issuer mode, against the REAL R2DBC
 * repository. Sibling to {@link ModerationDecideEscalationTest} (same harness style),
 * but for the OPPOSITE end of the workflow: the chain's first hop.
 *
 * <h2>Root cause this endpoint fixes</h2>
 * <p>{@code snapdragon-user-bff-api}'s {@code POST /bff/user/recommend-instance-block}
 * requires only ROLE_MATRIX/ROLE_MASTODON and forwards the caller's own JWT bearer,
 * unmodified, to federation-api. It used to POST straight to the mod-only
 * {@code /api/federation/moderation} {@code submit} surface
 * ({@code hasAnyRole('MOD','ADMIN','SUPERADMIN')}) — which NO {@code RoleHierarchy}
 * edge admits a plain ROLE_MATRIX/ROLE_MASTODON caller through, so the one caller who
 * could ever legitimately reach the user-bff-api endpoint got 403'd end-to-end. This
 * endpoint is the fix: a narrower, self-service surface, distinct from {@code submit},
 * that admits EXACTLY ROLE_MATRIX/ROLE_MASTODON and nothing wider.
 *
 * <h2>Categories asserted (comprehensive test standard)</h2>
 * <ul>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — a brand-X MATRIX/MASTODON caller creates a
 *       {@code recommended}/{@code instance-block} row stamped to their OWN brand.</li>
 *   <li><b>FAIL-CLOSED, GATE-IS-EXACT</b> — a plain USER, and even a MOD/ADMIN/
 *       SUPERADMIN (who freely reach the general submit surface), are 403'd HERE and
 *       create NO row — proving this narrower gate is exactly ROLE_MATRIX/MASTODON,
 *       never wider.</li>
 *   <li><b>KIND IS HARDCODED</b> — a caller-supplied {@code kind} field is ignored;
 *       the created row is ALWAYS {@code kind=instance-block}.</li>
 *   <li><b>DOMAIN STAMPING</b> — the row lands in the CALLER's own validated-issuer
 *       brand, never a body/param-supplied value.</li>
 *   <li><b>ANONYMOUS DENY</b> — no token is 401, no row created.</li>
 * </ul>
 *
 * <p>NO production code is changed by this test; it merely drives the existing chain.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ModerationRecommendInstanceBlockRoleGateTest extends PostgresTestSupport {

    private static final TestIssuer BRANDX = new TestIssuer();
    private static final TestIssuer BRANDY = new TestIssuer();

    @DynamicPropertySource
    static void tenancy(DynamicPropertyRegistry reg) {
        reg.add("app.tenancy.issuers",
                () -> BRANDX.issuerUri() + "=brandx," + BRANDY.issuerUri() + "=brandy");
    }

    @AfterAll
    static void stopIssuers() {
        BRANDX.close();
        BRANDY.close();
    }

    @Autowired WebTestClient web;
    @Autowired ModerationRequestRepository requests;

    @BeforeEach
    void clean() {
        requests.deleteAll().block();
    }

    private WebTestClient.RequestHeadersSpec<?> bearerPost(TestIssuer brand, String sub,
                                                            List<String> roles, String body) {
        return web.post().uri("/api/federation/moderation/recommend-instance-block")
                .header("Authorization", "Bearer " + brand.mint(sub, roles))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }

    private long rowCount() {
        return requests.findAllByOrderByTsDesc().count().block();
    }

    // ── USER-SITUATIONAL ALLOW: a platform participant files a recommendation ──

    @Test
    void matrixCaller_recommends_200_rowCreated_recommendedInstanceBlock_ownDomain() {
        bearerPost(BRANDX, "matrix-user", List.of("matrix"),
                "{\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange()
                .expectStatus().isOk();

        List<ModerationRequest> all = requests.findAllByOrderByTsDesc().collectList().block();
        assertThat(all).hasSize(1);
        ModerationRequest r = all.get(0);
        assertThat(r.getKind()).isEqualTo("instance-block");
        assertThat(r.getTarget()).isEqualTo("evil.example");
        assertThat(r.getStatus()).isEqualTo("recommended");
        assertThat(r.getRequester()).isEqualTo("matrix-user");
        assertThat(r.getDomain()).isEqualTo("brandx");
    }

    @Test
    void mastodonCaller_recommends_200_rowCreated() {
        bearerPost(BRANDX, "mastodon-user", List.of("mastodon"),
                "{\"target\":\"evil2.example\"}")
                .exchange()
                .expectStatus().isOk();

        List<ModerationRequest> all = requests.findAllByOrderByTsDesc().collectList().block();
        assertThat(all).hasSize(1);
        assertThat(all.get(0).getKind()).isEqualTo("instance-block");
        assertThat(all.get(0).getTarget()).isEqualTo("evil2.example");
    }

    @Test
    void brandYCaller_recommends_rowStampedToBrandY_notBrandX() {
        // Domain is taken from the VALIDATED ISSUER, never a body/param field.
        bearerPost(BRANDY, "matrix-user-y", List.of("matrix"),
                "{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isOk();

        ModerationRequest r = requests.findAllByOrderByTsDesc().blockFirst();
        assertThat(r.getDomain()).isEqualTo("brandy");
    }

    // ── KIND IS HARDCODED: a caller-supplied kind is ignored ──────────────────

    @Test
    void callerSuppliedKind_isIgnored_rowIsAlwaysInstanceBlock() {
        // RecommendInstanceBlockRequest has NO kind field to bind this to — Jackson
        // ignores the unknown property, and the controller always hardcodes
        // "instance-block". This is the structural guarantee that this narrower
        // surface can never be used to file a user-removal request.
        bearerPost(BRANDX, "matrix-user", List.of("matrix"),
                "{\"target\":\"someone\",\"kind\":\"user-removal\"}")
                .exchange()
                .expectStatus().isOk();

        ModerationRequest r = requests.findAllByOrderByTsDesc().blockFirst();
        assertThat(r.getKind()).isEqualTo("instance-block");
    }

    // ── FAIL-CLOSED, GATE-IS-EXACT: nobody else reaches this narrower surface ──

    @Test
    void plainUser_isForbidden_noRowCreated() {
        bearerPost(BRANDX, "plain-user", List.of("user"), "{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
        assertThat(rowCount()).isZero();
    }

    @Test
    void mod_isForbidden_evenThoughModReachesGeneralSubmit_noRowCreated() {
        // A MOD freely reaches POST / (the general submit surface) but must NOT get
        // an extra route in via this narrower, platform-participant-only path.
        bearerPost(BRANDX, "mod-x", List.of("mod"), "{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
        assertThat(rowCount()).isZero();
    }

    @Test
    void admin_isForbidden_noRowCreated() {
        bearerPost(BRANDX, "admin-x", List.of("admin"), "{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
        assertThat(rowCount()).isZero();
    }

    @Test
    void superadmin_isForbidden_noHierarchyEdgeToPlatformRoles_noRowCreated() {
        // SUPERADMIN's RoleHierarchy only reaches ADMIN/MOD/USER, never MATRIX/
        // MASTODON (leaf platform-participation flags, not a privilege tier) — so
        // even the cross-domain infra role gets no extra route in here.
        bearerPost(BRANDX, "su", List.of("superadmin"), "{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isForbidden();
        assertThat(rowCount()).isZero();
    }

    // ── ANONYMOUS DENY ──────────────────────────────────────────────────────

    @Test
    void anonymous_isUnauthorized_noRowCreated() {
        web.post().uri("/api/federation/moderation/recommend-instance-block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"target\":\"evil.example\"}")
                .exchange()
                .expectStatus().isUnauthorized();
        assertThat(rowCount()).isZero();
    }

    // ── VALIDATION: missing target is 400, no row created ──────────────────

    @Test
    void missingTarget_is400_noRowCreated() {
        bearerPost(BRANDX, "matrix-user", List.of("matrix"), "{}")
                .exchange()
                .expectStatus().isBadRequest();
        assertThat(rowCount()).isZero();
    }
}
