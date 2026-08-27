package net.hugmesh.federation.web;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import net.hugmesh.commons.security.DomainRegistry;

import net.hugmesh.federation.controller.VanityController;
import net.hugmesh.federation.model.FederationModule;
import net.hugmesh.federation.model.UserModule;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.federation.repository.UserModuleRepository;
import net.hugmesh.federation.repository.UsernameSkeletonRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.federation.service.UsernameAvailabilityService;
import net.hugmesh.federation.service.UsernameSkeletonService;
import net.hugmesh.federation.service.VanityPublishService;
import net.hugmesh.federation.service.VanityService;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * THE IDENTITY-AXIS REGRESSION SUITE for the vanity publish/unpublish write path.
 *
 * <h2>What was broken</h2>
 * Two DIFFERENT identity axes were being compared to each other, so no real user
 * could ever publish their public profile:
 *
 * <ul>
 *   <li><b>the LABEL axis</b> — {@code username}, a DNS label
 *       ({@code <username>.hugmesh.net}). user-bff-api addresses this endpoint by
 *       the label: {@code ProfileController.usernameOf(jwt)} reads
 *       {@code preferred_username} and {@code FederationApiClient.publishVanity}
 *       puts it in the path segment.</li>
 *   <li><b>the SUBJECT axis</b> — {@code jwt.getSubject()}, which on this platform
 *       is the Casdoor <b>UUID</b> (or the {@code provider:handle} composite on a
 *       bff_-session synthetic principal). It is the value
 *       {@code BundleController} stamps on every {@code user_modules} row as
 *       {@code owner_user_id}.</li>
 * </ul>
 *
 * <p>The pre-fix controller passed the SUBJECT into an owner guard that compared it
 * to the LABEL ({@code caller.equals(username)}), so every non-admin publish was a
 * 403 — and, stacked behind it, the bundle lookup filtered {@code user_modules} by
 * the LABEL when that column holds the SUBJECT, so merely relaxing the guard would
 * have converted the 403 into a 404.
 *
 * <p>The whole pre-existing suite is blind to this because every fixture builds a
 * JWT whose subject IS the username ({@code VanityControllerTest.jwtFor("alice")},
 * {@code VanityPublishServiceTest.publish("alice", …, "alice", …)}), collapsing the
 * two axes onto one value. EVERY test here therefore keeps subject and label
 * DISTINCT — that separation is the entire point of the file, and any fixture that
 * reunites them silently disarms the test.
 */
class VanityPublishIdentityAxisTest {

    /** A realistic Casdoor subject: a UUID, never the login name. */
    private static final String ALICE_UUID = "8c8f1a02-6f2e-4a1e-9a4d-7c1f0b2e5d33";
    private static final String ALICE_LABEL = "alice";
    private static final String SLUG = "profile-alice";

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    /** A REAL Casdoor-shaped access token: sub = UUID, preferred_username = login name. */
    private static Jwt casdoorJwt(String subject, String preferredUsername) {
        Jwt.Builder b = Jwt.withTokenValue("t")
                .header("alg", "none")
                .subject(subject)
                .claim("sub", subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (preferredUsername != null) {
            b.claim("preferred_username", preferredUsername);
        }
        return b.build();
    }

    private static SecurityContext ctx(String subject, String... roles) {
        var authorities = java.util.Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList();
        var sc = new SecurityContextImpl();
        sc.setAuthentication(new UsernamePasswordAuthenticationToken(subject, "n/a", authorities));
        return sc;
    }

    private static UserModule bundle(String ownerUserId) {
        UserModule m = new UserModule();
        m.setOwnerUserId(ownerUserId);
        m.setSlug(SLUG);
        m.setContentHash("deadbeef");
        m.setEntryFile("remoteEntry.json");
        m.setManifestJson("{}");
        m.setCreatedAt(Instant.now());
        return m;
    }

    /** Wiring holder so each test can assert on the mocks it cares about. */
    private record Rig(VanityController controller,
                       VanityPublishService publish,
                       FederationModuleRepository modules,
                       UserModuleRepository bundles,
                       UsernameSkeletonRepository skeletonRepo) {}

    private static Rig rig() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        UsernameSkeletonRepository skeletonRepo = mock(UsernameSkeletonRepository.class);
        UsernameSkeletonService skeletons = new UsernameSkeletonService();
        UsernameAvailabilityService usernames =
                new UsernameAvailabilityService(skeletons, skeletonRepo);

        // The best-effort skeleton mint must not blow up the publish.
        when(skeletonRepo.deleteById(anyString())).thenReturn(Mono.empty());
        when(skeletonRepo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService publish =
                new VanityPublishService(modules, bundles, usernames, skeletons);

        VanityService vanity = mock(VanityService.class);
        DomainRegistry domains = mock(DomainRegistry.class);
        when(domains.domainOf(any())).thenReturn("default");

        VanityController controller = new VanityController(vanity, skeletons, publish, domains);
        return new Rig(controller, publish, modules, bundles, skeletonRepo);
    }

    // ---------------------------------------------------------------------
    // THE HEADLINE: a real user publishing their OWN profile
    // ---------------------------------------------------------------------

    /**
     * THE REGRESSION. A plain ROLE_USER whose JWT subject is a Casdoor UUID
     * publishes their own vanity label. Pre-fix this was a 403 from
     * {@code ownerGuard}'s {@code caller.equals(username)} — a UUID is never equal
     * to a DNS label — which is exactly what every {@code PUT /bff/user/profile}
     * with Public + vanity enabled returned to the browser.
     */
    @Test
    void publish_ownProfile_withUuidSubjectAndUsernameClaim_succeeds() {
        Rig r = rig();
        when(r.bundles().findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                eq(SLUG), eq(ALICE_UUID))).thenReturn(Mono.just(bundle(ALICE_UUID)));
        when(r.modules().findBySlug(eq(SLUG))).thenReturn(Mono.empty());

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_UUID, ALICE_LABEL), ALICE_LABEL,
                                new VanityController.PublishRequest("Alice"))
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_UUID, "ROLE_USER")))))
                .assertNext(m -> {
                    assertThat(m.getSlug()).isEqualTo(SLUG);
                    assertThat(m.getVisibility()).isEqualTo("public");
                    assertThat(m.isEnabled()).isTrue();
                    assertThat(m.getDisplayName()).isEqualTo("Alice");
                })
                .verifyComplete();
    }

    /**
     * THE STACKED SECOND BUG. The {@code user_modules} lookup must filter by the
     * SUBJECT ({@code owner_user_id} is what {@code BundleController.put} stamps —
     * {@code jwt.getSubject()}), never by the DNS label. Filtering by the label
     * finds nothing and turns the fixed 403 into a 404, so this pins the finder
     * argument directly rather than trusting the happy path above.
     */
    @Test
    void publish_looksUpBundleBySubject_notByLabel() {
        Rig r = rig();
        // ONLY the subject-keyed lookup is stubbed; a label-keyed lookup returns
        // null from the mock, which Reactor surfaces as an NPE rather than a 404 —
        // either way this test fails if the axis is wrong.
        when(r.bundles().findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                eq(SLUG), eq(ALICE_UUID))).thenReturn(Mono.just(bundle(ALICE_UUID)));
        when(r.bundles().findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                eq(SLUG), eq(ALICE_LABEL))).thenReturn(Mono.empty());
        when(r.modules().findBySlug(eq(SLUG))).thenReturn(Mono.empty());

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_UUID, ALICE_LABEL), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_UUID, "ROLE_USER")))))
                .expectNextCount(1)
                .verifyComplete();

        verify(r.bundles()).findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                SLUG, ALICE_UUID);
        verify(r.bundles(), never())
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                        SLUG, ALICE_LABEL);
    }

    /**
     * The published fragment's {@code owner_user_id} must stay on the LABEL axis.
     * {@code VanityService}'s owner-ban gate resolves an active {@code scope=user}
     * override by that column, and the ban writer targets the username — stamping
     * the bundle's SUBJECT there would silently make every vanity-profile ban inert
     * while the fragment kept resolving at the vanity host.
     */
    @Test
    void publish_stampsLabelAsFragmentOwner_soTheOwnerBanStaysEffective() {
        Rig r = rig();
        when(r.bundles().findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                eq(SLUG), eq(ALICE_UUID))).thenReturn(Mono.just(bundle(ALICE_UUID)));
        when(r.modules().findBySlug(eq(SLUG))).thenReturn(Mono.empty());

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_UUID, ALICE_LABEL), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_UUID, "ROLE_USER")))))
                .assertNext(m -> {
                    assertThat(m.getOwnerUserId()).isEqualTo(ALICE_LABEL);
                    assertThat(m.getOwnerUserId()).isNotEqualTo(ALICE_UUID);
                    // and the cosmetic name must never fall back to a raw UUID
                    assertThat(m.getDisplayName()).isEqualTo(ALICE_LABEL);
                })
                .verifyComplete();
    }

    // ---------------------------------------------------------------------
    // REFUSAL: the guard must still refuse, on the RIGHT axis
    // ---------------------------------------------------------------------

    /**
     * CROSS-USER PUBLISH still 403s. Mallory (her own UUID, her own label) may not
     * publish alice's label. Moving the guard onto the label axis must not have
     * widened it — this is the case the fix could most easily have broken open.
     */
    @Test
    void publish_crossUser_isForbidden_andNeverTouchesTheStore() {
        Rig r = rig();
        String malloryUuid = "11111111-2222-3333-4444-555555555555";

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(malloryUuid, "mallory"), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(malloryUuid, "ROLE_USER")))))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode())
                            .isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();

        verify(r.bundles(), never())
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
        verify(r.modules(), never()).save(any());
    }

    /**
     * THE IMPERSONATION CASE THE FIX MUST NOT OPEN. Mallory forges a request whose
     * path segment is alice's label while her token carries her own claims — but
     * ALSO the reverse: a caller whose SUBJECT happens to equal the victim's LABEL
     * must still be refused, because the guard now reads the claim, not the subject.
     * A subject-shaped attacker string can no longer buy ownership of a label.
     */
    @Test
    void publish_subjectEqualToVictimLabel_isStillForbidden_whenClaimSaysOtherwise() {
        Rig r = rig();
        // Attacker controls a token whose SUBJECT is literally "alice" but whose
        // preferred_username (the login name Casdoor actually minted) is "mallory".
        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_LABEL, "mallory"), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_LABEL, "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN))
                .verify();

        verify(r.modules(), never()).save(any());
    }

    /**
     * A token with NO usable label claim at all (neither {@code preferred_username}
     * nor {@code name}) must FAIL CLOSED. The old {@code usernameOf}-style fallback
     * to the subject would hand a bff_-session composite ({@code google:a@b.com}) or
     * a UUID to the comparison; neither is a DNS label, so the only correct answer
     * is a refusal, never an accidental match.
     */
    @Test
    void publish_tokenWithoutLabelClaim_isForbidden() {
        Rig r = rig();

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_UUID, null), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_UUID, "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN))
                .verify();

        verify(r.modules(), never()).save(any());
    }

    /**
     * THE MUTATION-KILLING CASE for the deliberate absence of a subject fallback in
     * {@code VanityController.vanityLabelOf}.
     *
     * <p>The two refusal tests above do NOT discriminate it: one has a subject that is a
     * UUID (so a fallback still mismatches the label) and the other has a real
     * {@code preferred_username} (so the fallback never fires). The case a subject
     * fallback actually opens is the intersection — a token carrying NO label claim at
     * all whose SUBJECT happens to be a bare DNS label equal to the victim's. Restoring
     * {@code return jwt.getSubject();} to that helper makes this publish SUCCEED and
     * hands the caller ownership of a label they never proved they hold. (It is also the
     * pre-fix behaviour: the old guard's {@code caller.equals(username)} admitted exactly
     * this.) A missing label claim must be a refusal, never a guess.
     */
    @Test
    void publish_noLabelClaim_andSubjectEqualsVictimLabel_isForbidden() {
        Rig r = rig();
        // Subject is literally "alice" and there is NO preferred_username / name claim.
        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_LABEL, null), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_LABEL, "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN))
                .verify();

        verify(r.bundles(), never())
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
        verify(r.modules(), never()).save(any());
    }

    /** The same hole on the UNPUBLISH surface — a takedown must not be reachable by a
     *  claim-less token whose subject collides with the victim's label. */
    @Test
    void unpublish_noLabelClaim_andSubjectEqualsVictimLabel_isForbidden() {
        Rig r = rig();
        StepVerifier.create(r.controller()
                        .unpublish(casdoorJwt(ALICE_LABEL, null), ALICE_LABEL)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_LABEL, "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN))
                .verify();

        verify(r.modules(), never()).findBySlug(any());
    }

    /**
     * Casdoor's login name is not case-normalised ({@code ValidationPatterns.USERNAME}
     * accepts upper case) but the vanity label is a lower-cased DNS label, and
     * user-bff normalises before sending. A case-sensitive comparison would 403
     * every user whose Casdoor login name has a capital letter — the guard compares
     * case-insensitively, on the label axis.
     */
    @Test
    void publish_ownProfile_isCaseInsensitiveOnTheLabel() {
        Rig r = rig();
        when(r.bundles().findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                eq(SLUG), eq(ALICE_UUID))).thenReturn(Mono.just(bundle(ALICE_UUID)));
        when(r.modules().findBySlug(eq(SLUG))).thenReturn(Mono.empty());

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(ALICE_UUID, "Alice"), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_UUID, "ROLE_USER")))))
                .expectNextCount(1)
                .verifyComplete();
    }

    // ---------------------------------------------------------------------
    // ADMIN
    // ---------------------------------------------------------------------

    /**
     * An ADMIN publishes on another user's behalf. The admin's own subject is
     * useless as a bundle filter (the bundle belongs to alice), so the admin branch
     * must resolve the slug's active row WITHOUT the owner predicate — otherwise the
     * documented admin override silently 404s.
     */
    @Test
    void publish_admin_forAnotherUser_resolvesBundleWithoutOwnerPredicate() {
        Rig r = rig();
        String adminUuid = "99999999-8888-7777-6666-555555555555";
        when(r.bundles().findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(
                eq(SLUG), eq("default"))).thenReturn(Mono.just(bundle(ALICE_UUID)));
        when(r.modules().findBySlug(eq(SLUG))).thenReturn(Mono.empty());

        StepVerifier.create(r.controller()
                        .publish(casdoorJwt(adminUuid, "carol-admin"), ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(adminUuid, "ROLE_ADMIN")))))
                .assertNext(m -> assertThat(m.getOwnerUserId()).isEqualTo(ALICE_LABEL))
                .verifyComplete();

        verify(r.bundles(), never())
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
    }

    // ---------------------------------------------------------------------
    // UNPUBLISH — the symmetric surface, same two axes
    // ---------------------------------------------------------------------

    /** Unpublishing one's OWN profile must succeed on the label axis (pre-fix: 403). */
    @Test
    void unpublish_ownProfile_withUuidSubject_succeeds() {
        Rig r = rig();
        FederationModule existing = new FederationModule();
        existing.setSlug(SLUG);
        existing.setOwnerUserId(ALICE_LABEL);
        existing.setVisibility("public");
        existing.setEnabled(true);
        existing.setCreatedAt(Instant.now());
        when(r.modules().findBySlug(eq(SLUG))).thenReturn(Mono.just(existing));

        StepVerifier.create(r.controller()
                        .unpublish(casdoorJwt(ALICE_UUID, ALICE_LABEL), ALICE_LABEL)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(ALICE_UUID, "ROLE_USER")))))
                .verifyComplete();

        assertThat(existing.isEnabled()).isFalse();
        assertThat(existing.getVisibility()).isEqualTo("internal");
    }

    /** Cross-user UNPUBLISH — the takedown-by-stranger case — still 403s. */
    @Test
    void unpublish_crossUser_isForbidden() {
        Rig r = rig();
        String malloryUuid = "11111111-2222-3333-4444-555555555555";

        StepVerifier.create(r.controller()
                        .unpublish(casdoorJwt(malloryUuid, "mallory"), ALICE_LABEL)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx(malloryUuid, "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.FORBIDDEN))
                .verify();

        verify(r.modules(), never()).save(any());
    }

    /** An UNAUTHENTICATED-shaped token (no subject, no claims) is a 401, not a 403. */
    @Test
    void publish_missingSubject_isUnauthorized() {
        Rig r = rig();
        Jwt anon = Jwt.withTokenValue("t").header("alg", "none")
                .subject("")
                .claim("sub", "")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();

        StepVerifier.create(r.controller()
                        .publish(anon, ALICE_LABEL, null)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("", "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED))
                .verify();
    }
}
