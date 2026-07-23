package systems.hugmesh.federation.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.federation.model.CapabilityDto;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * END-TO-END coverage of the PUBLIC capability projection over the REAL
 * SecurityConfig chain + the REAL Liquibase-applied registry (NO mocked service —
 * the 010-2 seeds + 022 forum + 023/024/025 optional-service rows are present).
 *
 * <p>Asserts the design contract (optional-services CORRECTION 2):
 * <ul>
 *   <li>{@code GET /api/federation/capabilities} is {@code permitAll}: an ANONYMOUS
 *       caller (NO JWT) gets {@code 200}, NOT {@code 401} — unlike the authed,
 *       visibility-filtered {@code /api/federation/manifest};</li>
 *   <li>the body is the public-safe install-state set (slug + installed + mountAt +
 *       requiresRole) and INCLUDES the internal-visibility optional services
 *       (forum / mastodon / matrix / games) that the anon manifest would hide — so
 *       a logged-out host can grey them out;</li>
 *   <li>it omits internal-only detail: no remoteEntryUrl / ownerUserId /
 *       contentHash / raw metadata is on the wire.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
// Own Postgres container (a distinct @SpringBootTest context) via PostgresTestSupport
// so its Liquibase run is isolated from the other full-context tests.
class CapabilityEndpointTest extends PostgresTestSupport {

    @Autowired WebTestClient web;

    /** Anonymous (NO mockJwt) — the public read path. */
    @Test
    void capabilities_isPermitAll_anonymousGets200_not401() {
        web.get().uri("/api/federation/capabilities")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(CapabilityDto.class)
                .value(caps -> assertThat(caps).isNotEmpty());
    }

    /**
     * The anonymous body INCLUDES the internal-visibility optional services the
     * authed manifest would strip for a non-admin — that is the whole point: a
     * logged-out host learns the slug exists + its install-state, so it can grey it
     * out. All three new optional services + the forum are reported installed
     * (their seed rows are enabled + circuit-closed).
     */
    @Test
    void capabilities_includesOptionalServices_withInstallState_andMountAt() {
        List<CapabilityDto> caps = web.get().uri("/api/federation/capabilities")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(CapabilityDto.class)
                .returnResult().getResponseBody();

        assertThat(caps).extracting(CapabilityDto::slug)
                .contains("forum", "mastodon", "matrix", "games");

        assertCap(caps, "forum", "/social/forum", "forum");
        assertCap(caps, "mastodon", "/social/mastodon", "mastodon");
        assertCap(caps, "matrix", "/social/matrix", "matrix");
        assertCap(caps, "games", "/games", "ROLE_GAMES");
    }

    private static void assertCap(List<CapabilityDto> caps, String slug, String mountAt, String requiresRole) {
        CapabilityDto cap = caps.stream().filter(c -> c.slug().equals(slug)).findFirst().orElseThrow();
        assertThat(cap.installed()).as("%s seed row is enabled+closed => installed", slug).isTrue();
        assertThat(cap.mountAt()).isEqualTo(mountAt);
        assertThat(cap.requiresRole()).isEqualTo(requiresRole);
    }

    /**
     * The wire body exposes ONLY the four public-safe fields — no internal locator /
     * owner / hash / raw-metadata key may appear in the JSON. Guards against an
     * accidental widening of the projection leaking the manifest's internal detail
     * on the public endpoint.
     */
    @Test
    void capabilities_omitsInternalOnlyDetail_onTheWire() {
        String body = web.get().uri("/api/federation/capabilities")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult().getResponseBody();

        assertThat(body).isNotNull();
        // The public-safe keys ARE present...
        assertThat(body).contains("\"slug\"").contains("\"installed\"")
                .contains("\"mountAt\"").contains("\"requiresRole\"");
        // ...and NO internal-only key leaks through.
        assertThat(body)
                .doesNotContain("remoteEntryUrl")
                .doesNotContain("remote_entry_url")
                .doesNotContain("ownerUserId")
                .doesNotContain("contentHash")
                .doesNotContain("exposedModule")
                .doesNotContain("\"metadata\"")
                .doesNotContain("\"visibility\"");
    }
}
