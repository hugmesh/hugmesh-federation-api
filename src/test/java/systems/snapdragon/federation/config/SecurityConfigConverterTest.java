package systems.snapdragon.federation.config;

import org.junit.jupiter.api.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Casdoor JWT -> authority mapping. Same shape as admin-bff's
 * SecurityConfigConverterTest: the converter is package-private + static so it is
 * unit-tested directly against synthetic JWTs (no Spring context needed).
 */
class SecurityConfigConverterTest {

    private static Jwt jwt(Map<String, Object> claims) {
        Jwt.Builder b = Jwt.withTokenValue("tok")
                .header("alg", "none")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .subject("user-1");
        claims.forEach(b::claim);
        return b.build();
    }

    private static Set<String> authoritiesOf(Jwt jwt) {
        Converter<Jwt, Flux<GrantedAuthority>> conv = SecurityConfig.casdoorAuthoritiesConverter();
        return conv.convert(jwt).map(GrantedAuthority::getAuthority).collect(Collectors.toSet()).block();
    }

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
}
