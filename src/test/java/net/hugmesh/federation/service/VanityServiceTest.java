package net.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.federation.model.FederationModule;
import net.hugmesh.federation.model.FederationOverride;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.federation.repository.FederationOverrideRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Vanity-resolve service unit coverage (mocked repo + StepVerifier). Proves:
 * <ul>
 *   <li>an existing PUBLIC profile fragment resolves to its descriptor;</li>
 *   <li>a non-existent username -> empty Mono (controller maps to 404);</li>
 *   <li>the resolve only ever queries the public/enabled/circuit-closed finder,
 *       so an internal/disabled/broken fragment can never be returned;</li>
 *   <li>the in-code public-fragment guard rejects a non-public row even if the
 *       finder ever returned one (defence-in-depth);</li>
 *   <li>the slug convention is {@code profile-<username>}.</li>
 * </ul>
 * Fully reactive — assertions use {@link StepVerifier}, no blocking.
 */
class VanityServiceTest {

    private static FederationModule profileFragment(String username, String visibility, String hash) {
        FederationModule m = new FederationModule();
        m.setSlug(VanityService.profileSlug(username));
        m.setDisplayName(username + " — Profile");
        m.setKind("fragment");
        m.setOwnerUserId(username);
        m.setRemoteEntryUrl("/_fragments/profile-" + username + "/remoteEntry.json");
        m.setVersion("0.1.0");
        m.setContentHash(hash);
        m.setVisibility(visibility);
        m.setEnabled(true);
        m.setCircuitState("closed");
        m.setMetadata("{\"profile\":true}");
        return m;
    }

    private static FederationModuleRepository repoReturning(FederationModule m) {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                eq(VanityService.profileSlug("alice")), eq("fragment"), eq("public"), eq("closed")))
                .thenReturn(m == null ? Mono.empty() : Mono.just(m));
        return repo;
    }

    /** An override repo with NO active scope=user ban for any owner (the default). */
    private static FederationOverrideRepository noBan() {
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        when(overrides.findByScopeAndTargetAndClearedAtIsNull(any(), any()))
                .thenReturn(Flux.empty());
        return overrides;
    }

    /** VanityService over the given module repo + a no-ban override repo. */
    private static VanityService service(FederationModuleRepository repo) {
        return new VanityService(repo, noBan());
    }

    @Test
    void resolvesExistingPublicProfileFragment() {
        FederationModule alice = profileFragment("alice", "public", "deadbeefcafe");
        FederationModuleRepository repo = repoReturning(alice);
        VanityService svc = service(repo);

        StepVerifier.create(svc.resolve("alice"))
                .assertNext(dto -> {
                    assertThat(dto.username()).isEqualTo("alice");
                    assertThat(dto.slug()).isEqualTo("profile-alice");
                    assertThat(dto.kind()).isEqualTo("fragment");
                    assertThat(dto.visibility()).isEqualTo("public");
                    assertThat(dto.contentHash()).isEqualTo("deadbeefcafe");
                    // The content-addressed static path the host loads from.
                    assertThat(dto.fragmentPath())
                            .isEqualTo("/_fragments/profile-alice/deadbeefcafe/");
                })
                .verifyComplete();

        // The resolve ONLY ever asks for the public/enabled/circuit-closed row —
        // there is no code path to an internal fragment.
        verify(repo).findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                "profile-alice", "fragment", "public", "closed");
    }

    @Test
    void nonExistentUsername_isEmpty_soControllerReturns404() {
        FederationModuleRepository repo = repoReturning(null); // finder finds nothing
        VanityService svc = service(repo);

        StepVerifier.create(svc.resolve("alice"))
                .verifyComplete(); // empty Mono -> 404 in the controller
    }

    @Test
    void blankUsername_isEmpty() {
        VanityService svc = service(mock(FederationModuleRepository.class));
        StepVerifier.create(svc.resolve("  ")).verifyComplete();
        StepVerifier.create(svc.resolve(null)).verifyComplete();
    }

    @Test
    void nullContentHash_yieldsNullFragmentPath_butStillResolves() {
        // Module registered, bundle not yet synced: descriptor returned, path null,
        // so the host can distinguish "registered but no bytes" from "served".
        FederationModule alice = profileFragment("alice", "public", null);
        VanityService svc = service(repoReturning(alice));

        StepVerifier.create(svc.resolve("alice"))
                .assertNext(dto -> {
                    assertThat(dto.contentHash()).isNull();
                    assertThat(dto.fragmentPath()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void inCodeGuard_rejectsNonPublicRow_evenIfFinderReturnedOne() {
        // Belt-and-braces: if the finder ever returned an internal row, the
        // .filter(isPublicProfileFragment) drops it -> empty -> 404.
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        FederationModule internal = profileFragment("alice", "internal", "hash");
        when(repo.findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                eq("profile-alice"), eq("fragment"), eq("public"), eq("closed")))
                .thenReturn(Mono.just(internal));
        VanityService svc = service(repo);

        StepVerifier.create(svc.resolve("alice"))
                .verifyComplete(); // guard dropped it
    }

    @Test
    void inCodeGuard_rejectsNonFragmentKind() {
        FederationModule notFragment = profileFragment("alice", "public", "hash");
        notFragment.setKind("remote-shell");
        assertThat(VanityService.isPublicProfileFragment(notFragment)).isFalse();

        FederationModule ok = profileFragment("alice", "public", "hash");
        assertThat(VanityService.isPublicProfileFragment(ok)).isTrue();
        assertThat(VanityService.isPublicProfileFragment(null)).isFalse();
    }

    @Test
    void slugConvention_isProfileDashUsername() {
        assertThat(VanityService.profileSlug("alice")).isEqualTo("profile-alice");
        assertThat(VanityService.profileSlug("UsiDiamond")).isEqualTo("profile-UsiDiamond");
    }

    // ── Owner-ban gate (account-states foundation) ──────────────────────────────

    @Test
    void bannedOwner_is404_evenForPublicEnabledClosedFragment() {
        // The fragment IS public + enabled + circuit-closed (the finder returns it)…
        FederationModule alice = profileFragment("alice", "public", "deadbeefcafe");
        FederationModuleRepository repo = repoReturning(alice);

        // …but the owner (keyed on owner_user_id='alice') is under an ACTIVE
        // scope=user override (e.g. access_suspension), so the resolve is suppressed.
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        FederationOverride ban = new FederationOverride();
        ban.setScope("user");
        ban.setTarget("alice");
        ban.setReason("access_suspension:7");
        when(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "alice"))
                .thenReturn(Flux.just(ban));

        VanityService svc = new VanityService(repo, overrides);

        StepVerifier.create(svc.resolve("alice"))
                .verifyComplete(); // empty -> controller 404, despite a public fragment

        // Identity is pinned on owner_user_id (NOT the casdoor sub).
        verify(overrides).findByScopeAndTargetAndClearedAtIsNull("user", "alice");
    }

    @Test
    void unbannedOwner_resolvesNormally() {
        FederationModule alice = profileFragment("alice", "public", "deadbeefcafe");
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);
        when(overrides.findByScopeAndTargetAndClearedAtIsNull("user", "alice"))
                .thenReturn(Flux.empty()); // no active ban

        VanityService svc = new VanityService(repoReturning(alice), overrides);

        StepVerifier.create(svc.resolve("alice"))
                .assertNext(dto -> assertThat(dto.slug()).isEqualTo("profile-alice"))
                .verifyComplete();
    }

    @Test
    void nullOwnerFragment_neverConsultsBan_andResolves() {
        // A first-party / system fragment (owner_user_id NULL) can never match a
        // per-user ban; the resolve short-circuits without an override lookup.
        FederationModule sys = profileFragment("alice", "public", "deadbeefcafe");
        sys.setOwnerUserId(null);
        FederationOverrideRepository overrides = mock(FederationOverrideRepository.class);

        VanityService svc = new VanityService(repoReturning(sys), overrides);

        StepVerifier.create(svc.resolve("alice"))
                .assertNext(dto -> assertThat(dto.username()).isEqualTo("alice"))
                .verifyComplete();

        verify(overrides, org.mockito.Mockito.never())
                .findByScopeAndTargetAndClearedAtIsNull(any(), any());
    }
}
