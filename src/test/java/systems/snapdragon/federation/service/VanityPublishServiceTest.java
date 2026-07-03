package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.federation.repository.UsernameSkeletonRepository;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The owner-scoped self-publish/unpublish WRITE path unit coverage — the "missing
 * link" the federation-api README's <em>Vanity PUBLISH path (cross-service)</em>
 * section calls out. Mocked repos; assertions are reactive (StepVerifier).
 */
class VanityPublishServiceTest {

    private static UserModule bundle(String owner, String slug, String hash, String entryFile) {
        UserModule m = new UserModule();
        m.setOwnerUserId(owner);
        m.setSlug(slug);
        m.setContentHash(hash);
        m.setEntryFile(entryFile);
        m.setManifestJson("{}");
        m.setCreatedAt(Instant.now());
        return m;
    }

    private static FederationModule existingModule(String username, String visibility, boolean enabled) {
        FederationModule m = new FederationModule();
        m.setSlug(VanityService.profileSlug(username));
        m.setKind("fragment");
        m.setOwnerUserId(username);
        m.setDisplayName(username + " existing");
        m.setVisibility(visibility);
        m.setEnabled(enabled);
        m.setCircuitState("open"); // proves publish never clobbers an active kill-switch
        m.setVersion("1.0.0");
        m.setCreatedAt(Instant.now());
        return m;
    }

    /** Real (dependency-free) username services — no mocking needed for the
     *  reserved/confusable gate or the best-effort skeleton grant. */
    private static UsernameAvailabilityService realUsernames() {
        UsernameSkeletonRepository repo = mock(UsernameSkeletonRepository.class);
        when(repo.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(repo.deleteById(any(String.class))).thenReturn(Mono.empty());
        return new UsernameAvailabilityService(new UsernameSkeletonService(), repo);
    }

    private static VanityPublishService service(FederationModuleRepository modules, UserModuleRepository bundles) {
        return new VanityPublishService(modules, bundles, realUsernames(), new UsernameSkeletonService());
    }

    // ---- owner-scoping ----

    @Test
    void publish_nonOwnerNonAdmin_isForbidden_andNeverTouchesRepos() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("mallory", false, "alice", null, PrincipalDomain.forDomain("default")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();
        verify(bundles, never()).findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
        verify(modules, never()).findBySlug(any());
    }

    @Test
    void publish_adminOnBehalfOfAnotherUser_isAllowed() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, "a".repeat(64), "remoteEntry.json")));
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.empty());
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("admin-carol", true, "alice", null, PrincipalDomain.forDomain("default")))
                .assertNext(m -> assertThat(m.getSlug()).isEqualTo(slug))
                .verifyComplete();
    }

    @Test
    void unpublish_nonOwnerNonAdmin_isForbidden_andNeverTouchesRepo() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.unpublish("mallory", false, "alice"))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
                })
                .verify();
        verify(modules, never()).findBySlug(any());
    }

    // ---- reserved-name defence (write-layer, mirrors user-bff ProfileService.save) ----

    @Test
    void publish_reservedUsername_isRejected_beforeAnyBundleLookup() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("admin", false, "admin", null, PrincipalDomain.forDomain("default")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                })
                .verify();
        verify(bundles, never()).findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
    }

    @Test
    void publish_confusableOfReservedUsername_isRejected() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        VanityPublishService svc = service(modules, bundles);

        // "4dmin" is a confusable skeleton of the reserved label "admin".
        StepVerifier.create(svc.publish("4dmin", false, "4dmin", null, PrincipalDomain.forDomain("default")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                })
                .verify();
    }

    // ---- honest failure: no bundle uploaded yet ----

    @Test
    void publish_noUploadedBundle_is404_neverFakesSuccess() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.empty());

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("alice", false, "alice", null, PrincipalDomain.forDomain("default")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
                })
                .verify();
        verify(modules, never()).save(any());
    }

    // ---- upsert: create ----

    @Test
    void publish_firstTime_createsPublicEnabledFragment_fromCallersOwnBundle() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        String hash = "b".repeat(64);
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, hash, "card.json")));
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.empty());
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("alice", false, "alice", "Alice's Page", PrincipalDomain.forDomain("brand-x")))
                .assertNext(m -> {
                    assertThat(m.getSlug()).isEqualTo(slug);
                    assertThat(m.getKind()).isEqualTo("fragment");
                    assertThat(m.getOwnerUserId()).isEqualTo("alice");
                    assertThat(m.getVisibility()).isEqualTo("public");
                    assertThat(m.isEnabled()).isTrue();
                    assertThat(m.getContentHash()).isEqualTo(hash);
                    assertThat(m.getRemoteEntryUrl()).isEqualTo("/_fragments/" + slug + "/card.json");
                    assertThat(m.getDisplayName()).isEqualTo("Alice's Page");
                    assertThat(m.getDomain()).isEqualTo("brand-x");
                    assertThat(m.getVersion()).isNotBlank();
                })
                .verifyComplete();
    }

    /** No client-suppliable remoteEntryUrl/contentHash — proves the fragment is
     *  ALWAYS derived from the caller's own bundle row, never trusted input. */
    @Test
    void publish_neverTrustsClientSuppliedLocatorOrHash() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        String realHash = "c".repeat(64);
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, realHash, "remoteEntry.json")));
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.empty());
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        // publish() has no parameter for remoteEntryUrl/contentHash at all — the
        // only client input is displayName. Assert the persisted hash matches the
        // BUNDLE's hash, proving it was derived server-side.
        StepVerifier.create(svc.publish("alice", false, "alice", null, PrincipalDomain.forDomain("default")))
                .assertNext(m -> assertThat(m.getContentHash()).isEqualTo(realHash))
                .verifyComplete();
    }

    // ---- upsert: republish never clobbers an admin circuit-break ----

    @Test
    void publish_existingRow_refreshesButKeepsCircuitState() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        String hash = "d".repeat(64);
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, hash, "remoteEntry.json")));
        // existing row was previously unpublished (internal/disabled) AND circuit-broken
        // by an admin kill-switch — the circuit state must survive a republish.
        FederationModule existing = existingModule("alice", "internal", false);
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.just(existing));
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("alice", false, "alice", null, PrincipalDomain.forDomain("default")))
                .assertNext(m -> {
                    assertThat(m.getVisibility()).isEqualTo("public");
                    assertThat(m.isEnabled()).isTrue();
                    // NOT reset to "closed" — the admin's circuit-break survives a republish.
                    assertThat(m.getCircuitState()).isEqualTo("open");
                    assertThat(m.getContentHash()).isEqualTo(hash);
                })
                .verifyComplete();
    }

    // ---- republish never bypasses the admin per-module kill-switch ----

    /**
     * {@code OverrideController} {@code action=unpublish} (the admin per-module
     * kill-switch, e.g. a single-profile moderation action) sets ONLY
     * {@code enabled=false} — unlike THIS service's own {@link VanityPublishService#unpublish},
     * it never touches {@code visibility}. A row left {@code visibility=public} /
     * {@code enabled=false} is therefore admin-suppressed, not self-unpublished, and
     * a republish must fail closed (409) rather than silently flip {@code enabled}
     * back to {@code true} — the documented recovery is admin-only, via
     * {@code POST /api/federation/overrides/{moduleSlug}/rearm}.
     */
    @Test
    void publish_adminKillSwitchedRow_isRejectedWith409_neverReEnabled() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, "e".repeat(64), "remoteEntry.json")));
        // admin kill-switch signature: still visibility=public, but enabled=false —
        // NOT internal (that would mean this service's own unpublish ran instead).
        FederationModule adminSuppressed = existingModule("alice", "public", false);
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.just(adminSuppressed));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("alice", false, "alice", null, PrincipalDomain.forDomain("default")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                })
                .verify();
        verify(modules, never()).save(any());
    }

    /** The guard applies even when the caller is ROLE_ADMIN/ROLE_SUPERADMIN — the
     *  only sanctioned recovery is the dedicated {@code /rearm} endpoint, never a
     *  republish through this owner-scoped write path. */
    @Test
    void publish_adminKillSwitchedRow_stillRejectedForAdminCaller() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, "f".repeat(64), "remoteEntry.json")));
        FederationModule adminSuppressed = existingModule("alice", "public", false);
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.just(adminSuppressed));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("admin-carol", true, "alice", null, PrincipalDomain.forDomain("default")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
                })
                .verify();
        verify(modules, never()).save(any());
    }

    /** A row suppressed via THIS service's own unpublish (visibility=internal,
     *  enabled=false) is the normal self-service republish case and must still
     *  succeed — the guard must not conflate it with the admin kill-switch. */
    @Test
    void publish_selfUnpublishedRow_republishesNormally_isNotConflatedWithAdminSuppression() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("alice")))
                .thenReturn(Mono.just(bundle("alice", slug, "0".repeat(64), "remoteEntry.json")));
        FederationModule selfUnpublished = existingModule("alice", "internal", false);
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.just(selfUnpublished));
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("alice", false, "alice", null, PrincipalDomain.forDomain("default")))
                .assertNext(m -> {
                    assertThat(m.getVisibility()).isEqualTo("public");
                    assertThat(m.isEnabled()).isTrue();
                })
                .verifyComplete();
    }

    /** A never-before-published (brand new) row is never treated as admin-suppressed
     *  — {@code createdAt} is only ever non-null once a prior publish has landed. */
    @Test
    void publish_firstTime_isNeverTreatedAsAdminSuppressed() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("brandnew");
        when(bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(eq(slug), eq("brandnew")))
                .thenReturn(Mono.just(bundle("brandnew", slug, "1".repeat(64), "remoteEntry.json")));
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.empty());
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.publish("brandnew", false, "brandnew", null, PrincipalDomain.forDomain("default")))
                .assertNext(m -> assertThat(m.isEnabled()).isTrue())
                .verifyComplete();
    }

    // ---- unpublish ----

    @Test
    void unpublish_flipsToInternalDisabled_neverDeletes() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("alice");
        FederationModule existing = existingModule("alice", "public", true);
        existing.setCircuitState("closed");
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.just(existing));
        when(modules.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.unpublish("alice", false, "alice"))
                .verifyComplete();
        verify(modules, never()).delete(any(FederationModule.class));
        verify(modules).save(argThatVisibilityInternalAndDisabled());
    }

    @Test
    void unpublish_neverPublished_isIdempotentNoOp() {
        FederationModuleRepository modules = mock(FederationModuleRepository.class);
        UserModuleRepository bundles = mock(UserModuleRepository.class);
        String slug = VanityService.profileSlug("ghost");
        when(modules.findBySlug(eq(slug))).thenReturn(Mono.empty());

        VanityPublishService svc = service(modules, bundles);

        StepVerifier.create(svc.unpublish("ghost", false, "ghost"))
                .verifyComplete();
        verify(modules, never()).save(any());
    }

    private static FederationModule argThatVisibilityInternalAndDisabled() {
        return org.mockito.ArgumentMatchers.argThat(m ->
                m != null && "internal".equals(m.getVisibility()) && !m.isEnabled());
    }
}
