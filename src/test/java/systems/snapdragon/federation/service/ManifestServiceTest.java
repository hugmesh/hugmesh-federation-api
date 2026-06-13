package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;

import systems.snapdragon.federation.security.DomainScope;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The keystone test: manifest filtering by visibility / enabled / circuit-state +
 * the ACTIVE scope-override read-path cut (kill-switch scope=all|user|role).
 *
 * <p>The repository finder already excludes disabled + circuit-open rows
 * (DB-side); ManifestService then applies the visibility/role cut IN CODE and the
 * active scope-override cut (loaded reactively via
 * {@code findByScopeInAndClearedAtIsNull}). The Cassandra write-through cache is a
 * no-op stub here (graceful-degrade path).
 */
class ManifestServiceTest {

    private static FederationModule module(String slug, String visibility) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug);
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setVersion("1.0.0");
        m.setVisibility(visibility);
        m.setEnabled(true);
        m.setCircuitState("closed");
        return m;
    }

    private static FederationModule owned(String slug, String ownerUserId) {
        FederationModule m = module(slug, "public");
        m.setOwnerUserId(ownerUserId);
        return m;
    }

    private static FederationModule withMetadata(String slug, String metadata) {
        FederationModule m = module(slug, "public");
        m.setMetadata(metadata);
        return m;
    }

    /** An internal-visibility module carrying metadata (the seeded wiki/forum shape:
     *  visibility='internal' + {"requiresRole":..,"mountAt":..}). */
    private static FederationModule withInternalMetadata(String slug, String metadata) {
        FederationModule m = module(slug, "internal");
        m.setMetadata(metadata);
        return m;
    }

    private static FederationOverride scope(String scope, String target) {
        FederationOverride o = new FederationOverride();
        o.setScope(scope);
        o.setTarget(target);
        o.setAction("circuit-break");
        o.setSetBy("admin-1");
        return o;
    }

    @SuppressWarnings("unchecked")
    private static ManifestCache noopCache() {
        ManifestCache cache = mock(ManifestCache.class);
        when(cache.put(any())).thenReturn(Mono.empty());
        return cache;
    }

    /** No active scope overrides (the common case). The DEFAULT-domain render path
     *  consults the DOMAIN-scoped finder, so that is what we stub. */
    private static FederationOverrideRepository noScopeOverrides() {
        FederationOverrideRepository repo = mock(FederationOverrideRepository.class);
        when(repo.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), anyString()))
                .thenReturn(Flux.empty());
        return repo;
    }

    private static FederationOverrideRepository activeScope(FederationOverride... active) {
        FederationOverrideRepository repo = mock(FederationOverrideRepository.class);
        when(repo.findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), anyString()))
                .thenReturn(Flux.just(active));
        return repo;
    }

    @Test
    void anonymousCaller_seesOnlyPublicRows() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(module("login", "public"), module("admin", "internal")));

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("login");
    }

    @Test
    void adminCaller_seesInternalRows_too() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(module("login", "public"), module("admin", "internal")));

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER", "ROLE_ADMIN")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("login", "admin");
    }

    @Test
    void readPath_queriesOnlyCircuitClosedRows() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), noopCache());
        StepVerifier.create(svc.render(Set.of("ROLE_ADMIN")))
                .assertNext(m -> assertThat(m.remotes()).isEmpty())
                .verifyComplete();

        // The kill-switch contract: a circuit-broken remote is dropped because
        // the manifest only ever asks for circuit_state='closed' (DEFAULT-domain).
        verify(repo).findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", "default");
    }

    @Test
    void writesThroughCache_onlyForPublicView() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(module("login", "public")));
        ManifestCache cache = noopCache();

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), cache);
        // Non-admin (public) render writes through.
        svc.render(Set.of("ROLE_USER")).block();
        verify(cache).put(any());
    }

    /**
     * The wiki is REGISTERED INERT (changeset 028): visibility='internal' so the
     * row is HIDDEN from anonymous / plain-user callers in the manifest read path
     * until the snapdragon-wiki-ui surface ships. A ROLE_USER caller must NOT see it
     * — exactly the catalog cut that keeps the inert module out of ordinary users'
     * manifests. (The wiki row carries metadata.requiresRole='wiki', mountAt '/wiki'
     * per 028; modelled here to mirror the seeded shape.)
     */
    @Test
    void wikiModule_internal_isHiddenFromPlainUser() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(
                        module("login", "public"),
                        withInternalMetadata("wiki", "{\"requiresRole\":\"wiki\",\"mountAt\":\"/wiki\"}")));

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER")).block();

        // The inert wiki row is filtered out; only the public 'login' remote ships.
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("login");
    }

    /**
     * The admin/internal catalog cut: a ROLE_ADMIN caller DOES see the
     * internal-visibility wiki row in the manifest read path (so admins can manage
     * the surface once it exists), while plain users do not. Mirrors
     * {@link #adminCaller_seesInternalRows_too}.
     */
    @Test
    void wikiModule_internal_isVisibleToAdmin() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(
                        module("login", "public"),
                        withInternalMetadata("wiki", "{\"requiresRole\":\"wiki\",\"mountAt\":\"/wiki\"}")));

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER", "ROLE_ADMIN")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("login", "wiki");
    }

    @Test
    void visibilityHelper_defaultsUnknownToVisible() {
        assertThat(ManifestService.isVisibleTo(module("x", "public"), false)).isTrue();
        assertThat(ManifestService.isVisibleTo(module("x", "internal"), false)).isFalse();
        assertThat(ManifestService.isVisibleTo(module("x", "internal"), true)).isTrue();
        assertThat(ManifestService.isVisibleTo(module("x", null), false)).isTrue();
        assertThat(ManifestService.isVisibleTo(module("x", "weird"), false)).isTrue();
    }

    // ----- ACTIVE SCOPE-OVERRIDE read-path cut -----

    @Test
    void scopeAll_active_killsEverything_andCachesEmptyPublicView() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(module("login", "public"), module("admin", "internal")));
        ManifestCache cache = noopCache();

        // scope=all carries a NULL target — matches every module (global kill).
        ManifestService svc = new ManifestService(repo, activeScope(scope("all", null)), cache);

        StepVerifier.create(svc.render(Set.of("ROLE_USER")))
                .assertNext(m -> assertThat(m.remotes()).isEmpty())
                .verifyComplete();

        // The cache contract holds: the public render still writes through, and the
        // cached body is the empty (scope-filtered) public-safe view.
        verify(cache).put(any());
    }

    @Test
    void scopeAll_active_killsEverything_evenForAdmin() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(module("login", "public"), module("admin", "internal")));
        ManifestCache cache = noopCache();

        ManifestService svc = new ManifestService(repo, activeScope(scope("all", null)), cache);

        FederationManifestDto manifest = svc.render(Set.of("ROLE_ADMIN")).block();
        assertThat(manifest.remotes()).isEmpty();
        // Admin render does NOT write through (unchanged cache rule).
        verify(cache, never()).put(any());
    }

    @Test
    void scopeUser_active_dropsThatOwnersModules_keepsOthers() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(
                        owned("ownerX-game", "ownerX"),
                        owned("ownerY-game", "ownerY"),
                        module("system-host", "public"))); // NULL owner = system

        ManifestService svc = new ManifestService(repo, activeScope(scope("user", "ownerX")), noopCache());

        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER")).block();
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("ownerY-game", "system-host");
    }

    @Test
    void scopeRole_active_dropsModulesDeclaringThatRequiredRole_othersUnaffected() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(
                        withMetadata("admin", "{\"requiresRole\":\"admin\"}"),
                        withMetadata("login", "{\"public\":true}"),   // no requiresRole
                        module("host", "public")));                    // null metadata

        // scope=role target=admin (case-insensitive match).
        ManifestService svc = new ManifestService(repo, activeScope(scope("role", "ADMIN")), noopCache());

        FederationManifestDto manifest = svc.render(Set.of("ROLE_ADMIN")).block();
        // Documents the limitation in-test: only modules DECLARING requiresRole=admin
        // are dropped; modules without it (login, host) are unaffected by scope=role.
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("login", "host");
    }

    @Test
    void clearedScope_isNotActive_soAllModulesRestored() {
        // The repo finder for the active set returns EMPTY (the override was
        // cleared => cleared_at IS NOT NULL => excluded). Modules are restored.
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(owned("ownerX-game", "ownerX"), module("host", "public")));

        ManifestService svc = new ManifestService(repo, noScopeOverrides(), noopCache());

        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER")).block();
        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("ownerX-game", "host");
    }

    @Test
    void perModuleSlugOverride_isNotInActiveScopeSet_noRegression() {
        // A circuit-broken module was already mutated to circuit_state='open' at
        // apply time, so the DB finder NEVER returns it; there is no active scope
        // row. The read path is unchanged from today.
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc(eq("closed"), eq("default")))
                .thenReturn(Flux.just(module("login", "public"))); // the broken one not returned
        FederationOverrideRepository ovr = noScopeOverrides();

        ManifestService svc = new ManifestService(repo, ovr, noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("login");
        // The active-scope finder is consulted exactly once per render (DEFAULT-domain).
        verify(ovr).findByScopeInAndClearedAtIsNullAndDomain(anyCollection(), eq("default"));
    }

    @Test
    void requiresRoleParse_isNullSafe() {
        assertThat(ManifestService.requiresRole(null)).isNull();
        assertThat(ManifestService.requiresRole("")).isNull();
        assertThat(ManifestService.requiresRole("not-json")).isNull();
        assertThat(ManifestService.requiresRole("{\"public\":true}")).isNull();
        assertThat(ManifestService.requiresRole("{\"requiresRole\":\"admin\"}")).isEqualTo("admin");
    }

    @Test
    void isSuppressedByScope_matchesPerScope() {
        FederationModule sys = module("host", "public");                 // null owner, null metadata
        FederationModule mine = owned("mine", "u1");
        FederationModule adminUi = withMetadata("admin", "{\"requiresRole\":\"admin\"}");

        // scope=all matches everything.
        List<FederationOverride> all = List.of(scope("all", null));
        assertThat(ManifestService.isSuppressedByScope(sys, all)).isTrue();
        assertThat(ManifestService.isSuppressedByScope(mine, all)).isTrue();

        // scope=user matches only the named owner.
        List<FederationOverride> userU1 = List.of(scope("user", "u1"));
        assertThat(ManifestService.isSuppressedByScope(mine, userU1)).isTrue();
        assertThat(ManifestService.isSuppressedByScope(sys, userU1)).isFalse();

        // scope=role matches only declared requiresRole.
        List<FederationOverride> roleAdmin = List.of(scope("role", "admin"));
        assertThat(ManifestService.isSuppressedByScope(adminUi, roleAdmin)).isTrue();
        assertThat(ManifestService.isSuppressedByScope(sys, roleAdmin)).isFalse();

        // empty active set suppresses nothing.
        assertThat(ManifestService.isSuppressedByScope(adminUi, List.of())).isFalse();
    }

    /** Compile-time guard that the finder signature accepts a Collection<String>. */
    @SuppressWarnings("unused")
    private static Collection<String> scopeKinds() {
        return List.of("all", "user", "role");
    }
}
