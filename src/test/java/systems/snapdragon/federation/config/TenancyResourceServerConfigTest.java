package systems.snapdragon.federation.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import systems.snapdragon.federation.security.DomainRegistry;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link TenancyResourceServerConfig} — the CONFIG-GATED multi-issuer (per-brand
 * Casdoor) wiring. The adversarial verify flagged its FAIL-CLOSED allowlist
 * (an unknown / untrusted issuer yields NO manager -&gt; 401 before any authority is
 * emitted) as correct-by-construction but UNTESTED; this pins both the gate and the
 * allowlist predicate. Sibling of the gateway's
 * {@code TenancyResourceServerConfigConditionalTest}, adjusted to the federation-api's
 * issuer-only (no host) registry + constructor.
 *
 * <ul>
 *   <li><b>The conditional</b> — the bean (and its {@code tenantAuthManagerResolver})
 *       must be ABSENT when {@code app.tenancy.issuers} is unset OR the EMPTY string
 *       (the {@code ${APP_TENANCY_ISSUERS:}} default a bare {@code @ConditionalOnProperty}
 *       would have wrongly activated), and PRESENT only once real {@code issuer=domain}
 *       pairs arrive.</li>
 *   <li><b>The allowlist (FAIL-CLOSED)</b> — the resolver only ever hands out a manager
 *       for a TRUSTED issuer ({@link DomainRegistry#isTrusted}); an unknown / null iss
 *       is rejected (no manager -&gt; 401).</li>
 * </ul>
 */
class TenancyResourceServerConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of())
            .withUserConfiguration(TestRegistryConfig.class, TenancyResourceServerConfig.class)
            // The single-issuer jwk-set-uri the back-compat decoder would bind to —
            // present in every deployment; never network-touched here (the resolver
            // builds decoders lazily, per issuer, on first token sight).
            .withPropertyValues(
                    "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://casdoor:8000",
                    "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://casdoor:8000/jwks");

    /** A DomainRegistry primed from the SAME properties the runner sets, so the
     *  conditional config under test can construct. */
    @org.springframework.context.annotation.Configuration
    static class TestRegistryConfig {
        @org.springframework.context.annotation.Bean
        DomainRegistry domainRegistry(
                @org.springframework.beans.factory.annotation.Value(
                        "${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String issuer,
                @org.springframework.beans.factory.annotation.Value(
                        "${app.tenancy.issuers:}") String issuers) {
            return new DomainRegistry(issuer, issuers);
        }
    }

    // ── The conditional (config-gating) ──────────────────────────────────────────

    @Test
    void default_noTenancyIssuers_doesNotContributeResolver() {
        // No app.tenancy.issuers at all — the multi-issuer config + its resolver bean
        // must be ABSENT, so SecurityConfig keeps the single-issuer jwk-set-uri path.
        runner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(TenancyResourceServerConfig.class);
            assertThat(ctx.getBeanNamesForType(ReactiveAuthenticationManagerResolver.class))
                    .as("no tenant resolver bean on the default/single-issuer context")
                    .isEmpty();
        });
    }

    @Test
    void emptyTenancyIssuers_theApplicationYmlDefault_doesNotContributeResolver() {
        // app.tenancy.issuers="" (the ${APP_TENANCY_ISSUERS:} default) is "present and
        // not false" — a bare @ConditionalOnProperty would WRONGLY activate the bean.
        // The .contains('=') guard keeps it absent.
        runner.withPropertyValues("app.tenancy.issuers=").run(ctx -> {
            assertThat(ctx).doesNotHaveBean(TenancyResourceServerConfig.class);
            assertThat(ctx.getBeanNamesForType(ReactiveAuthenticationManagerResolver.class))
                    .as("empty issuers must NOT activate the tenant resolver")
                    .isEmpty();
        });
    }

    @Test
    void populatedTenancyIssuers_contributesResolver() {
        // Real issuer=domain pairs -> the conditional fires and the resolver bean is
        // present (multi-brand mode). Built lazily, so no Casdoor is contacted here.
        runner.withPropertyValues(
                        "app.tenancy.issuers=https://id.brandx.tld=brandx,https://id.brandy.tld=brandy")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(TenancyResourceServerConfig.class);
                    assertThat(ctx).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
                });
    }

    // ── The allowlist (FAIL-CLOSED on an unknown / untrusted issuer) ─────────────

    @Test
    void allowlist_isExactlyTheTrustedIssuers_unknownIssuerIsRejected() {
        // The resolver's allowlist is exactly DomainRegistry.trustedIssuers(): a token
        // whose iss is not in that set gets NO manager (Mono.empty) -> 401 before any
        // authority is emitted. The resolver keys off registry.isTrusted(issuer), so
        // assert that predicate is the fail-closed gate.
        DomainRegistry multi = new DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy");
        // trusted issuers DO get through
        assertThat(multi.isTrusted("https://id.brandx.tld")).isTrue();
        assertThat(multi.isTrusted("https://id.brandy.tld")).isTrue();
        // an unknown / untrusted / null iss is rejected (no manager -> 401)
        assertThat(multi.isTrusted("https://evil.attacker.tld")).isFalse();
        assertThat(multi.isTrusted(null)).isFalse();
        assertThat(multi.trustedIssuers())
                .as("the manager allowlist is exactly the configured per-brand Casdoors")
                .containsExactlyInAnyOrder("https://id.brandx.tld", "https://id.brandy.tld");
    }
}
