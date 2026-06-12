package systems.snapdragon.federation.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DomainScope#resolve(Jwt, DomainRegistry)} — the per-request DOMAIN PREDICATE
 * resolved at the controller boundary. The adversarial verify flagged the FAIL-CLOSED
 * branch (an untrusted / unresolved issuer must yield the {@link DomainScope#NO_DOMAIN}
 * sentinel — which matches ZERO rows — NOT the SUPERADMIN un-scoped bypass) as
 * correct-by-construction but UNTESTED. This pins it.
 *
 * <p>Three shapes:
 * <ul>
 *   <li>TRUSTED issuer, non-superadmin -&gt; the issuer-derived domain (the per-domain
 *       pinned finder is run).</li>
 *   <li>SUPERADMIN -&gt; the cross-domain (un-scoped) tier: {@code domain()==null},
 *       {@code isSuperadmin()==true}.</li>
 *   <li>UNTRUSTED / UNRESOLVED issuer, non-superadmin -&gt; {@code NO_DOMAIN}
 *       (fail-closed): {@code isSuperadmin()==false} AND {@code domain()!=null} (it is
 *       the sentinel) — so a domain-pinned query returns EMPTY rather than silently
 *       going cross-domain or un-pinned.</li>
 * </ul>
 */
class DomainScopeTest {

    /** Single-issuer registry: every token -> "default" (back-compat). */
    private static final DomainRegistry SINGLE = new DomainRegistry(
            "https://id.snapdragon.systems", "");

    /** Multi-brand registry: brandx + brandy issuers map to distinct domains; any
     *  other issuer is UNTRUSTED (registry yields null). */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

    private static Jwt jwt(String issuer, Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("tok")
                .header("alg", "none")
                .issuer(issuer)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject("user-1");
        claims.forEach(b::claim);
        return b.build();
    }

    // ── TRUSTED issuer -> that brand's domain (the ALLOW path) ───────────────────

    @Test
    void trustedIssuer_nonSuperadmin_pinsToIssuerDomain() {
        DomainScope sx = DomainScope.resolve(jwt("https://id.brandx.example", Map.of()), MULTI);
        assertThat(sx.isSuperadmin()).isFalse();
        assertThat(sx.domain()).isEqualTo("brandx");

        DomainScope sy = DomainScope.resolve(jwt("https://id.brandy.example", Map.of()), MULTI);
        assertThat(sy.isSuperadmin()).isFalse();
        assertThat(sy.domain()).isEqualTo("brandy");
    }

    @Test
    void singleIssuer_nonSuperadmin_pinsToDefault() {
        DomainScope s = DomainScope.resolve(jwt("https://id.snapdragon.systems", Map.of()), SINGLE);
        assertThat(s.isSuperadmin()).isFalse();
        assertThat(s.domain()).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
    }

    // ── SUPERADMIN -> cross-domain (un-scoped) tier ──────────────────────────────

    @Test
    void superadmin_isCrossDomain_unscoped_regardlessOfIssuer() {
        // Even an UNTRUSTED issuer: the super-role short-circuits to the un-scoped tier
        // (it is the infra control plane). domain()==null, isSuperadmin()==true.
        DomainScope s = DomainScope.resolve(
                jwt("https://evil.attacker.example", Map.of("roles", List.of("superadmin"))), MULTI);
        assertThat(s.isSuperadmin()).isTrue();
        assertThat(s.domain()).isNull();
    }

    @Test
    void superadmin_hyphenAndUnderscoreSpellings_alsoUnscoped() {
        for (String role : List.of("super-admin", "SUPER_ADMIN")) {
            DomainScope s = DomainScope.resolve(
                    jwt("https://id.brandx.example", Map.of("roles", List.of(role))), MULTI);
            assertThat(s.isSuperadmin()).as(role).isTrue();
            assertThat(s.domain()).as(role).isNull();
        }
    }

    // ── FAIL-CLOSED: untrusted / unresolved issuer -> NO_DOMAIN sentinel ─────────

    @Test
    void untrustedIssuer_nonSuperadmin_failsClosedToNoDomainSentinel_notBypass() {
        // The keystone fail-closed branch. An untrusted issuer (registry -> null)
        // with NO super-role must NOT become the un-scoped bypass: it becomes the
        // NO_DOMAIN sentinel so a domain-pinned finder matches ZERO rows.
        DomainScope s = DomainScope.resolve(jwt("https://evil.attacker.example", Map.of()), MULTI);
        assertThat(s.isSuperadmin())
                .as("an unresolved issuer must NOT be treated as the cross-domain super-role")
                .isFalse();
        assertThat(s.domain())
                .as("fail-closed: a non-superadmin with an unresolved issuer is pinned to the "
                        + "no-match sentinel, never left null (un-pinned)")
                .isEqualTo(DomainScope.NO_DOMAIN);
        // The sentinel can never equal a real (sanitised) domain.
        assertThat(s.domain()).doesNotMatch("[a-z0-9-]+");
    }

    @Test
    void noDomainSentinel_isNeverNull_soQueryStaysPinned() {
        // Belt-and-suspenders contract: a non-superadmin scope's domain() is NEVER
        // null, so a domain-scoped query can never accidentally become un-pinned.
        DomainScope failed = DomainScope.resolve(jwt("https://unknown.example", Map.of()), MULTI);
        assertThat(failed.domain()).isNotNull();
        assertThat(DomainScope.of(null).domain())
                .as("even an explicit null domain collapses to the no-match sentinel")
                .isEqualTo(DomainScope.NO_DOMAIN);
    }

    // ── factory shapes (the explicit / internal constructors) ────────────────────

    @Test
    void superadminFactory_isUnscoped_and_ofFactory_isPerDomain() {
        assertThat(DomainScope.superadmin().isSuperadmin()).isTrue();
        assertThat(DomainScope.superadmin().domain()).isNull();
        assertThat(DomainScope.of("brandx").isSuperadmin()).isFalse();
        assertThat(DomainScope.of("brandx").domain()).isEqualTo("brandx");
    }
}
