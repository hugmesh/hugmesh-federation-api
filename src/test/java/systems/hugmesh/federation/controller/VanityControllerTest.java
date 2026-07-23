package systems.hugmesh.federation.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.model.VanityProfileDto;
import systems.hugmesh.federation.service.UsernameSkeletonService;
import systems.hugmesh.federation.service.VanityPublishService;
import systems.hugmesh.federation.service.VanityService;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Vanity controller unit coverage: the host-header first-label extraction, the
 * reserved-subdomain defence, and the empty-resolve -> 404 mapping. The service is
 * mocked; assertions are reactive (StepVerifier).
 */
class VanityControllerTest {

    /** Real (dependency-free) skeleton service — its reserved-skeleton set drives
     *  the READ-LAYER confusable-of-reserved 404 the controller now applies. */
    private static final UsernameSkeletonService SKEL = new UsernameSkeletonService();

    private static VanityProfileDto dto(String username) {
        return new VanityProfileDto(username, "profile-" + username, username + " — Profile",
                "fragment", "/_fragments/profile-" + username + "/remoteEntry.json", null,
                "0.1.0", "hash", "public", "/_fragments/profile-" + username + "/hash/", null);
    }

    /** Build a controller with a real {@link UsernameSkeletonService} and a
     *  {@link DomainRegistry} that maps any issuer to {@code "default"} (the write
     *  paths' per-domain scoping is exercised in {@code VanityPublishServiceTest}).
     *  A no-op {@link VanityPublishService} mock is supplied for tests that do not
     *  exercise the publish/unpublish endpoints. */
    private static VanityController controller(VanityService svc) {
        return controller(svc, mock(VanityPublishService.class));
    }

    private static VanityController controller(VanityService svc, VanityPublishService publishSvc) {
        DomainRegistry domains = mock(DomainRegistry.class);
        when(domains.domainOf(any())).thenReturn("default");
        return new VanityController(svc, SKEL, publishSvc, domains);
    }

    private static Jwt jwtFor(String subject) {
        return Jwt.withTokenValue("t")
                .header("alg", "none")
                .subject(subject)
                .claim("sub", subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    /** A security context whose authentication carries the given authorities. */
    private static SecurityContext ctx(String subject, String... roles) {
        var authorities = java.util.Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList();
        var auth = new UsernamePasswordAuthenticationToken(subject, "n/a", authorities);
        var sc = new org.springframework.security.core.context.SecurityContextImpl();
        sc.setAuthentication(auth);
        return sc;
    }

    // ---- firstLabel: the FIRST DNS LABEL of the Host header is the username ----

    @Test
    void firstLabel_extractsUsername_fromVanityHost() {
        assertThat(VanityController.firstLabel("alice.snapdragon.systems")).isEqualTo("alice");
        // strips a :port and lower-cases.
        assertThat(VanityController.firstLabel("Alice.snapdragon.systems:443")).isEqualTo("alice");
        // deeper sub-labels: still the FIRST label.
        assertThat(VanityController.firstLabel("alice.dev.snapdragon.systems")).isEqualTo("alice");
    }

    @Test
    void firstLabel_returnsNull_forApexOrEmpty() {
        // The apex (domain.tld) has no username label.
        assertThat(VanityController.firstLabel("snapdragon.systems")).isNull();
        assertThat(VanityController.firstLabel("")).isNull();
        assertThat(VanityController.firstLabel(null)).isNull();
        assertThat(VanityController.firstLabel("localhost")).isNull();
    }

    // ---- reserved labels: service subdomains are NOT usernames ----

    @Test
    void reservedSubdomain_is404_notResolved() {
        VanityService svc = mock(VanityService.class);
        VanityController c = controller(svc);

        StepVerifier.create(c.resolve("api"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                })
                .verify();

        // A reserved label never reaches the service.
        verify(svc, never()).resolve(any());
    }

    static Set<String> reservedLabels() {
        return ReservedNames.RESERVED_LABELS;
    }

    /**
     * EVERY label in the canonical reserved set must hard-404 (prefix-collision:
     * a username that exactly equals a reserved app route / subdomain) and must
     * NEVER reach the resolve service. This is the serving-layer half of the
     * reserved-username guard (the DB CHECK in 016 is the other half).
     */
    @ParameterizedTest
    @MethodSource("reservedLabels")
    void everyReservedLabel_is404_andNeverHitsService(String label) {
        VanityService svc = mock(VanityService.class);
        VanityController c = controller(svc);

        StepVerifier.create(c.resolve(label))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                })
                .verify();
        // case-insensitive: the upper-cased label is reserved too.
        StepVerifier.create(c.resolve(label.toUpperCase()))
                .expectError(ResponseStatusException.class)
                .verify();

        verify(svc, never()).resolve(any());
    }

    /**
     * The default-on Kiwix wiki reserves the {@code wiki} label (ReservedNames +
     * changeset 027): a vanity username {@code wiki} must hard-404 (so it can never
     * collide with the {@code wiki.<domain>} subdomain / {@code /wiki} apex mount)
     * and must NEVER reach the resolve service — case-insensitively. Mirrors the
     * forum guard. This is the serving-layer half; the DB CHECK on
     * {@code profile-wiki} (027) is the other half.
     */
    @Test
    void wikiVanityUsername_is404_andNeverHitsService() {
        VanityService svc = mock(VanityService.class);
        VanityController c = controller(svc);

        StepVerifier.create(c.resolve("wiki"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                })
                .verify();
        StepVerifier.create(c.resolve("WIKI"))
                .expectError(ResponseStatusException.class)
                .verify();
        // The vanity HOST form (wiki.snapdragon.systems) is rejected the same way.
        StepVerifier.create(c.resolveByHost("wiki.snapdragon.systems"))
                .expectError(ResponseStatusException.class)
                .verify();

        verify(svc, never()).resolve(any());
    }

    @Test
    void resolveByHost_reservedHost_is404() {
        VanityService svc = mock(VanityService.class);
        VanityController c = controller(svc);

        StepVerifier.create(c.resolveByHost("api.snapdragon.systems"))
                .expectError(ResponseStatusException.class)
                .verify();
        verify(svc, never()).resolve(any());
    }

    @Test
    void resolveByHost_apexHost_is404_noUsername() {
        VanityService svc = mock(VanityService.class);
        VanityController c = controller(svc);

        StepVerifier.create(c.resolveByHost("snapdragon.systems"))
                .expectError(ResponseStatusException.class)
                .verify();
        verify(svc, never()).resolve(any());
    }

    // ---- happy path + empty -> 404 ----

    @Test
    void resolve_existingPublicProfile_returnsDescriptor() {
        VanityService svc = mock(VanityService.class);
        when(svc.resolve(eq("alice"))).thenReturn(Mono.just(dto("alice")));
        VanityController c = controller(svc);

        StepVerifier.create(c.resolve("alice"))
                .assertNext(d -> assertThat(d.slug()).isEqualTo("profile-alice"))
                .verifyComplete();
    }

    @Test
    void resolve_emptyService_mapsTo404() {
        VanityService svc = mock(VanityService.class);
        when(svc.resolve(eq("ghost"))).thenReturn(Mono.empty());
        VanityController c = controller(svc);

        StepVerifier.create(c.resolve("ghost"))
                .expectErrorSatisfies(e ->
                        assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND))
                .verify();
    }

    @Test
    void resolveByHost_vanityHost_delegatesWithFirstLabel() {
        VanityService svc = mock(VanityService.class);
        when(svc.resolve(eq("alice"))).thenReturn(Mono.just(dto("alice")));
        VanityController c = controller(svc);

        StepVerifier.create(c.resolveByHost("alice.snapdragon.systems:443"))
                .assertNext(d -> assertThat(d.username()).isEqualTo("alice"))
                .verifyComplete();
        verify(svc).resolve("alice");
    }

    // ---- READ-LAYER: a CONFUSABLE of a reserved label hard-404s, no DB hit ----

    /**
     * The read-layer defence: a first label that is NOT an exact reserved label but
     * whose SKELETON equals a reserved-label skeleton ({@code 4dmin ~ admin},
     * {@code v4ult ~ vault}, {@code r00t ~ root}) must hard-404 and NEVER reach the
     * resolve service — even though no {@code profile-4dmin} fragment exists. This
     * catches anything that slipped past the write gate via backfill / race / ICU
     * shift, with an O(1) precomputed-set membership check (no DB hit).
     */
    @Test
    void confusableOfReservedLabel_is404_andNeverHitsService() {
        VanityService svc = mock(VanityService.class);
        VanityController c = controller(svc);

        for (String confusable : new String[] {"4dmin", "v4ult", "r00t"}) {
            StepVerifier.create(c.resolve(confusable))
                    .expectErrorSatisfies(e -> {
                        assertThat(e).isInstanceOf(ResponseStatusException.class);
                        assertThat(((ResponseStatusException) e).getStatusCode())
                                .isEqualTo(HttpStatus.NOT_FOUND);
                    })
                    .verify();
        }
        verify(svc, never()).resolve(any());
    }

    /**
     * A clean (non-reserved, non-confusable) username still resolves through the
     * service — the read-layer skeleton gate does not over-block real usernames.
     */
    @Test
    void cleanUsername_passesThroughTheReadLayerSkeletonGate() {
        VanityService svc = mock(VanityService.class);
        when(svc.resolve(eq("alice"))).thenReturn(Mono.just(dto("alice")));
        VanityController c = controller(svc);

        StepVerifier.create(c.resolve("alice"))
                .assertNext(d -> assertThat(d.slug()).isEqualTo("profile-alice"))
                .verifyComplete();
        verify(svc).resolve("alice");
    }

    // ---- publish / unpublish: the AUTHENTICATED owner-scoped write path ----

    private static FederationModule module(String username) {
        FederationModule m = new FederationModule();
        m.setSlug("profile-" + username);
        m.setKind("fragment");
        m.setOwnerUserId(username);
        m.setVisibility("public");
        m.setEnabled(true);
        return m;
    }

    /** The controller forwards the JWT SUBJECT as the caller (never a request
     *  param), resolves the ADMIN flag from the reactive security context, and
     *  hands the request body's displayName + a resolved scope straight through to
     *  {@link VanityPublishService#publish}. */
    @Test
    void publish_forwardsSubjectAdminAndDisplayName_toService() {
        VanityService svc = mock(VanityService.class);
        VanityPublishService publishSvc = mock(VanityPublishService.class);
        when(publishSvc.publish(eq("alice"), eq(false), eq("alice"), eq("Alice"), any()))
                .thenReturn(Mono.just(module("alice")));
        VanityController c = controller(svc, publishSvc);

        StepVerifier.create(c.publish(jwtFor("alice"), "alice", new VanityController.PublishRequest("Alice"))
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_USER")))))
                .assertNext(m -> assertThat(m.getSlug()).isEqualTo("profile-alice"))
                .verifyComplete();
    }

    /** A null request body is a valid publish (no displayName override) — the
     *  controller must not NPE and must forward a null displayName. */
    @Test
    void publish_nullBody_forwardsNullDisplayName() {
        VanityService svc = mock(VanityService.class);
        VanityPublishService publishSvc = mock(VanityPublishService.class);
        when(publishSvc.publish(eq("alice"), eq(true), eq("alice"), isNull(), any()))
                .thenReturn(Mono.just(module("alice")));
        VanityController c = controller(svc, publishSvc);

        StepVerifier.create(c.publish(jwtFor("alice"), "alice", null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_ADMIN")))))
                .expectNextCount(1)
                .verifyComplete();
    }

    /** A federation-layer publish failure (e.g. no uploaded bundle yet, or a
     *  cross-owner attempt) propagates as an error — the controller must never
     *  swallow it into a fabricated success. */
    @Test
    void publish_serviceError_propagates_neverFakesSuccess() {
        VanityService svc = mock(VanityService.class);
        VanityPublishService publishSvc = mock(VanityPublishService.class);
        when(publishSvc.publish(eq("mallory"), eq(false), eq("alice"), any(), any()))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "not owner")));
        VanityController c = controller(svc, publishSvc);

        StepVerifier.create(c.publish(jwtFor("mallory"), "alice", null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("mallory", "ROLE_USER")))))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();
    }

    @Test
    void unpublish_forwardsSubjectAndAdmin_toService_andCompletesEmpty() {
        VanityService svc = mock(VanityService.class);
        VanityPublishService publishSvc = mock(VanityPublishService.class);
        when(publishSvc.unpublish(eq("alice"), eq(false), eq("alice"))).thenReturn(Mono.empty());
        VanityController c = controller(svc, publishSvc);

        StepVerifier.create(c.unpublish(jwtFor("alice"), "alice")
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_USER")))))
                .verifyComplete();
    }

    @Test
    void unpublish_serviceError_propagates_neverFakesSuccess() {
        VanityService svc = mock(VanityService.class);
        VanityPublishService publishSvc = mock(VanityPublishService.class);
        when(publishSvc.unpublish(eq("mallory"), eq(false), eq("alice")))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "not owner")));
        VanityController c = controller(svc, publishSvc);

        StepVerifier.create(c.unpublish(jwtFor("mallory"), "alice")
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("mallory", "ROLE_USER")))))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();
    }
}
