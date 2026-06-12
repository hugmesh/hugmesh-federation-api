package systems.snapdragon.federation.config;

import org.junit.jupiter.api.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Casdoor JWT -&gt; authority mapping, delineated USER-SITUATIONAL (the per-claim
 * mapping a single principal produces) and CROSS-USER (the authority-injection
 * regressions that stop a brand-X token forging another brand's tenant scope or the
 * super-role). Exercises the CANONICAL {@link CasdoorAuthorities} converter the
 * single-issuer + multi-issuer paths share — package-private + static so it is
 * unit-tested directly against synthetic JWTs (no Spring context needed).
 */
class SecurityConfigConverterTest {

    /** Single-issuer registry: every token -> DOMAIN_default (back-compat). */
    private static final DomainRegistry SINGLE = new DomainRegistry(
            "https://id.snapdragon.systems", "");

    /** Multi-brand registry: brandx + brandy issuers map to distinct domains. */
    private static final DomainRegistry MULTI = new DomainRegistry(
            "",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

    private static Jwt jwt(Map<String, Object> claims) {
        return jwt("https://id.snapdragon.systems", claims);
    }

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

    private static Set<String> authoritiesOf(DomainRegistry registry, Jwt jwt) {
        Converter<Jwt, Flux<GrantedAuthority>> conv = CasdoorAuthorities.converter(registry);
        return conv.convert(jwt).map(GrantedAuthority::getAuthority).collect(Collectors.toSet()).block();
    }

    private static Set<String> authoritiesOf(Jwt jwt) {
        return authoritiesOf(SINGLE, jwt);
    }

    // ───────────────────────────── USER-SITUATIONAL ─────────────────────────────

    @Test
    void everyPrincipalGetsRoleUserFloor() {
        assertThat(authoritiesOf(jwt(Map.of()))).contains("ROLE_USER");
    }

    @Test
    void stringRolesBecomeUpperRoleAuthorities() {
        Set<String> a = authoritiesOf(jwt(Map.of("roles", List.of("admin", "mod"))));
        assertThat(a).contains("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
    }

    @Test
    void objectRolesWithNameClaim() {
        Set<String> a = authoritiesOf(jwt(Map.of("roles", List.of(Map.of("name", "internal")))));
        assertThat(a).contains("ROLE_INTERNAL");
    }

    @Test
    void permissionsBecomeVerbatimAuthorities() {
        Set<String> a = authoritiesOf(jwt(Map.of("permissions", List.of("federation:write"))));
        assertThat(a).contains("federation:write");
    }

    @Test
    void isAdminFlagAddsRoleAdmin() {
        assertThat(authoritiesOf(jwt(Map.of("isAdmin", true)))).contains("ROLE_ADMIN");
    }

    @Test
    void singleIssuer_stampsDomainDefault() {
        // Back-compat: a single-issuer cluster emits exactly one DOMAIN_default and
        // nothing else changes.
        assertThat(authoritiesOf(jwt(Map.of()))).contains("DOMAIN_default");
    }

    @Test
    void multiIssuer_stampsDomainFromValidatedIssuer() {
        // The DOMAIN_<x> authority is keyed on the cryptographically-validated issuer,
        // NOT a user-settable claim: brandx's issuer -> DOMAIN_brandx.
        Set<String> bx = authoritiesOf(MULTI, jwt("https://id.brandx.example", Map.of()));
        assertThat(bx).contains("DOMAIN_brandx").doesNotContain("DOMAIN_brandy");
        Set<String> by = authoritiesOf(MULTI, jwt("https://id.brandy.example", Map.of()));
        assertThat(by).contains("DOMAIN_brandy").doesNotContain("DOMAIN_brandx");
    }

    // ───── CROSS-USER: authority-injection regressions (the foundation lesson) ─────

    @Test
    void crossUser_forgedDomainPermission_isDropped_issuerWins() {
        // A brandx token carrying permissions:["DOMAIN_brandy"] must NOT forge a
        // brandy tenant scope. The reserved-prefix guard drops the verbatim entry;
        // the validated issuer stamps the ONLY DOMAIN_ (brandx).
        Set<String> a = authoritiesOf(MULTI,
                jwt("https://id.brandx.example", Map.of("permissions", List.of("DOMAIN_brandy"))));
        assertThat(a).contains("DOMAIN_brandx");
        assertThat(a).doesNotContain("DOMAIN_brandy");
        // Exactly one DOMAIN_ authority survives — the issuer's.
        assertThat(a.stream().filter(s -> s.startsWith("DOMAIN_")).count()).isEqualTo(1L);
    }

    @Test
    void crossUser_forgedSuperadminPermission_isDropped() {
        // permissions:["ROLE_SUPERADMIN"] must NOT forge the super-role: reserved
        // ROLE_ prefix entries from the permissions claim are dropped.
        Set<String> a = authoritiesOf(
                jwt(Map.of("permissions", List.of("ROLE_SUPERADMIN"))));
        assertThat(a).doesNotContain("ROLE_SUPERADMIN");
    }

    @Test
    void crossUser_rolesEntryNamedDomain_becomesInertRoleAuthority_notTenantScope() {
        // A roles entry "DOMAIN_x" is ALWAYS ROLE_-prefixed first -> ROLE_DOMAIN_X
        // (inert, non-tenant); it can never become a DOMAIN_ tenant scope.
        Set<String> a = authoritiesOf(MULTI,
                jwt("https://id.brandx.example", Map.of("roles", List.of("DOMAIN_brandy"))));
        assertThat(a).contains("ROLE_DOMAIN_BRANDY");
        assertThat(a).doesNotContain("DOMAIN_brandy");
        assertThat(a.stream().filter(s -> s.startsWith("DOMAIN_")).count()).isEqualTo(1L);
    }

    @Test
    void crossUser_rolesEntryNamedLikeADomain_isInert_notATenantScope() {
        // A bare roles entry "brandy" (a real DOMAIN value) cannot grant brandy's
        // tenant scope: it gains the ROLE_ prefix -> ROLE_BRANDY (inert), while the
        // ONLY DOMAIN_ stays the validated issuer's (brandx).
        Set<String> a = authoritiesOf(MULTI,
                jwt("https://id.brandx.example", Map.of("roles", List.of("brandy"))));
        assertThat(a).contains("ROLE_BRANDY", "DOMAIN_brandx");
        assertThat(a).doesNotContain("DOMAIN_brandy");
        assertThat(a.stream().filter(s -> s.startsWith("DOMAIN_")).count()).isEqualTo(1L);
    }

    @Test
    void crossUser_reservedPrefixGuard_isCaseAndWhitespaceInsensitive() {
        // The reserved-prefix guard upper-cases + trims before matching, so neither a
        // lower-case nor a leading-whitespace spelling of a reserved-prefix permission
        // can sneak a forged ROLE_/DOMAIN_ authority through. Each of these verbatim
        // permission entries must be DROPPED.
        Set<String> a = authoritiesOf(MULTI, jwt("https://id.brandx.example", Map.of(
                "permissions", List.of(
                        "domain_brandy",        // lower-case DOMAIN_ -> dropped
                        "  DOMAIN_brandy",      // leading whitespace -> dropped
                        "role_superadmin",      // lower-case ROLE_ -> dropped
                        " ROLE_ADMIN ",         // padded ROLE_ -> dropped
                        "federation:read"))));  // a legit non-reserved perm -> kept
        assertThat(a).contains("DOMAIN_brandx", "federation:read");
        assertThat(a).doesNotContain("DOMAIN_brandy", "domain_brandy", "  DOMAIN_brandy");
        assertThat(a).doesNotContain("ROLE_SUPERADMIN", "role_superadmin", " ROLE_ADMIN ");
        // No forged ROLE_ADMIN sneaks in via the padded permission entry, and exactly
        // one (issuer) DOMAIN_ survives.
        assertThat(a).doesNotContain("ROLE_ADMIN");
        assertThat(a.stream().filter(s -> s.startsWith("DOMAIN_")).count()).isEqualTo(1L);
    }

    @Test
    void singleIssuer_emitsExactlyOneDomainDefault_withRoleUserFloor() {
        // Single-issuer back-compat: ROLE_USER floor + exactly one DOMAIN_default and
        // nothing else moves.
        Set<String> a = authoritiesOf(jwt(Map.of()));
        assertThat(a).contains("ROLE_USER", "DOMAIN_default");
        assertThat(a.stream().filter(s -> s.startsWith("DOMAIN_")).count()).isEqualTo(1L);
    }
}
