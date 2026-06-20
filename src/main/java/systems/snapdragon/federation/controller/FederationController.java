package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.service.ManifestService;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Runtime federation manifest, served from PostgreSQL (Cassandra write-through
 * cached). Lifted from the games {@code FederationController}: the Angular host
 * bootstrap fetches this and feeds {@code remotes} into native-federation's
 * {@code initFederation(...)} before {@code bootstrapApplication}, so new remote
 * modules appear without redeploying the host shell.
 *
 * <p>Gated as {@code authenticated} (see SecurityConfig); the manifest is then
 * visibility/role-filtered IN CODE by {@link ManifestService} against the
 * caller's authorities. Internal-visibility remotes only appear for
 * ROLE_ADMIN / ROLE_INTERNAL callers; circuit-open + disabled remotes are
 * dropped for everyone.
 */
@Tag(name = "Federation", description = "Runtime module-federation manifest (DB-backed, visibility + kill-switch filtered).")
@RestController
@RequestMapping("/api/federation")
public class FederationController {

    private final ManifestService manifest;
    private final DomainRegistry domains;

    public FederationController(ManifestService manifest, DomainRegistry domains) {
        this.manifest = manifest;
        this.domains = domains;
    }

    @Operation(
        summary = "Active federation manifest",
        description = """
            Returns every enabled + circuit-closed `federation_modules` row the
            caller may see (public to all; internal only to ROLE_ADMIN /
            ROLE_INTERNAL), ordered by kind then slug, as {generatedAt, remotes[]}.
            The host calls this on bootstrap + every full reload.
            """)
    @GetMapping("/manifest")
    public Mono<FederationManifestDto> manifest(Authentication auth, @AuthenticationPrincipal Jwt jwt) {
        // The manifest is DOMAIN-scoped: a per-domain principal sees ONLY their own
        // brand's remotes; SUPERADMIN (cross-domain infra role) sees every brand's.
        // The domain is derived from the cryptographically-validated issuer (via the
        // registry), never a spoofable claim — fail-closed to a no-match domain when
        // the issuer is unknown in multi-brand mode.
        return manifest.render(authoritiesOf(auth), PrincipalDomain.resolve(jwt, domains));
    }

    static Set<String> authoritiesOf(Authentication auth) {
        if (auth == null || auth.getAuthorities() == null) return Set.of();
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }
}
