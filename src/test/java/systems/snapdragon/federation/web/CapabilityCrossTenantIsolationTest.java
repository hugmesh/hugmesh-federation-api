package systems.snapdragon.federation.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.federation.model.CapabilityDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BUG-A end-to-end proof: the PUBLIC {@code GET /api/federation/capabilities}
 * projection over the REAL SecurityConfig chain + REAL Liquibase H2 store does NOT
 * leak another brand's registered services NOR any per-user
 * {@code profile-<username>} vanity fragment. An ANONYMOUS caller resolves to the
 * {@code "default"} domain, so the DOMAIN-pinned, fragment-excluding finder returns
 * only the default-domain non-fragment rows.
 *
 * <p>FAIL-FIRST against the unfixed service (which ran the unscoped {@code findAll()}):
 * the seeded {@code brandy-secret} row AND the {@code profile-victim} fragment WOULD
 * both appear in the anonymous body — turning the public endpoint into a cross-brand
 * registry + username enumeration oracle. The DENY assertions below catch exactly that.
 *
 * <p>Isolation note mirrors {@link CapabilityEndpointTest}: own H2 mem DB so its
 * Liquibase run + seeded rows do not collide with other full-context tests.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "spring.r2dbc.url=r2dbc:h2:mem:///fed_capabilities_xtenant;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;USER=sa;PASSWORD=",
        "spring.liquibase.url=jdbc:h2:mem:fed_capabilities_xtenant;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;NON_KEYWORDS=ACTION,TARGET,VALUE,KEY,VERSION;DATABASE_TO_LOWER=TRUE"
})
class CapabilityCrossTenantIsolationTest {

    @Autowired WebTestClient web;
    @Autowired FederationModuleRepository modules;

    @BeforeEach
    void seed() {
        // A brand-Y registered service the default-domain anonymous caller must NEVER
        // learn about (cross-tenant), and a per-user profile-<username> vanity fragment
        // the public projection must NEVER surface (username enumeration oracle).
        modules.save(svc("brandy-secret", "remote-shell", "brandy")).block();
        modules.save(svc("profile-victim", "fragment", "default")).block();
    }

    private static FederationModule svc(String slug, String kind, String domain) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind(kind);
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility("public");
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setMetadata("{\"mountAt\":\"/x/" + slug + "\"}");
        m.setDomain(domain);
        return m;
    }

    @Test
    void anonymousCapabilities_excludeOtherBrandRows_andProfileFragments() {
        List<CapabilityDto> caps = web.get().uri("/api/federation/capabilities")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(CapabilityDto.class)
                .returnResult().getResponseBody();

        assertThat(caps).isNotEmpty();
        List<String> slugs = caps.stream().map(CapabilityDto::slug).toList();

        // USER-SITUATIONAL ALLOW: the default-domain seeded optional services still show.
        assertThat(slugs).contains("forum", "games");

        // CROSS-USER DENY: the brand-Y row is invisible to a default-domain caller.
        assertThat(slugs)
                .as("a default-domain anonymous caller must not see another brand's service")
                .doesNotContain("brandy-secret");

        // CROSS-USER DENY: NO profile-<username> vanity fragment may leak through the
        // public projection (enumeration oracle).
        assertThat(slugs)
                .as("the public capability projection must never surface a profile-<username> slug")
                .noneMatch(s -> s.startsWith("profile-"));
    }
}
