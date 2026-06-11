package systems.snapdragon.federation.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.model.VanityProfileDto;
import systems.snapdragon.federation.service.UsernameSkeletonService;
import systems.snapdragon.federation.service.VanityService;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
        VanityController c = new VanityController(svc, SKEL);

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
        VanityController c = new VanityController(svc, SKEL);

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

    @Test
    void resolveByHost_reservedHost_is404() {
        VanityService svc = mock(VanityService.class);
        VanityController c = new VanityController(svc, SKEL);

        StepVerifier.create(c.resolveByHost("api.snapdragon.systems"))
                .expectError(ResponseStatusException.class)
                .verify();
        verify(svc, never()).resolve(any());
    }

    @Test
    void resolveByHost_apexHost_is404_noUsername() {
        VanityService svc = mock(VanityService.class);
        VanityController c = new VanityController(svc, SKEL);

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
        VanityController c = new VanityController(svc, SKEL);

        StepVerifier.create(c.resolve("alice"))
                .assertNext(d -> assertThat(d.slug()).isEqualTo("profile-alice"))
                .verifyComplete();
    }

    @Test
    void resolve_emptyService_mapsTo404() {
        VanityService svc = mock(VanityService.class);
        when(svc.resolve(eq("ghost"))).thenReturn(Mono.empty());
        VanityController c = new VanityController(svc, SKEL);

        StepVerifier.create(c.resolve("ghost"))
                .expectErrorSatisfies(e ->
                        assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND))
                .verify();
    }

    @Test
    void resolveByHost_vanityHost_delegatesWithFirstLabel() {
        VanityService svc = mock(VanityService.class);
        when(svc.resolve(eq("alice"))).thenReturn(Mono.just(dto("alice")));
        VanityController c = new VanityController(svc, SKEL);

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
        VanityController c = new VanityController(svc, SKEL);

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
        VanityController c = new VanityController(svc, SKEL);

        StepVerifier.create(c.resolve("alice"))
                .assertNext(d -> assertThat(d.slug()).isEqualTo("profile-alice"))
                .verifyComplete();
        verify(svc).resolve("alice");
    }
}
