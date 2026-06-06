package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The keystone test: manifest filtering by visibility / enabled / circuit-state.
 *
 * <p>The repository finder already excludes disabled + circuit-open rows
 * (DB-side); ManifestService then applies the visibility/role cut IN CODE. This
 * verifies both the code cut (internal rows hidden from non-admin callers, shown
 * to admins) AND that the closed-only finder is the one queried (so the
 * circuit-break kill-switch drops a remote). The Cassandra write-through cache is
 * a no-op stub here (graceful-degrade path).
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

    @SuppressWarnings("unchecked")
    private static ManifestCache noopCache() {
        ManifestCache cache = mock(ManifestCache.class);
        when(cache.put(any())).thenReturn(Mono.empty());
        return cache;
    }

    @Test
    void anonymousCaller_seesOnlyPublicRows() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(eq("closed")))
                .thenReturn(Flux.just(module("login", "public"), module("admin", "internal")));

        ManifestService svc = new ManifestService(repo, noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("login");
    }

    @Test
    void adminCaller_seesInternalRows_too() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(eq("closed")))
                .thenReturn(Flux.just(module("login", "public"), module("admin", "internal")));

        ManifestService svc = new ManifestService(repo, noopCache());
        FederationManifestDto manifest = svc.render(Set.of("ROLE_USER", "ROLE_ADMIN")).block();

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactlyInAnyOrder("login", "admin");
    }

    @Test
    void readPath_queriesOnlyCircuitClosedRows() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(eq("closed")))
                .thenReturn(Flux.empty());

        ManifestService svc = new ManifestService(repo, noopCache());
        StepVerifier.create(svc.render(Set.of("ROLE_ADMIN")))
                .assertNext(m -> assertThat(m.remotes()).isEmpty())
                .verifyComplete();

        // The kill-switch contract: a circuit-broken remote is dropped because
        // the manifest only ever asks for circuit_state='closed'.
        verify(repo).findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed");
    }

    @Test
    void writesThroughCache_onlyForPublicView() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc(eq("closed")))
                .thenReturn(Flux.just(module("login", "public")));
        ManifestCache cache = noopCache();

        ManifestService svc = new ManifestService(repo, cache);
        // Non-admin (public) render writes through.
        svc.render(Set.of("ROLE_USER")).block();
        verify(cache).put(any());
    }

    @Test
    void visibilityHelper_defaultsUnknownToVisible() {
        assertThat(ManifestService.isVisibleTo(module("x", "public"), false)).isTrue();
        assertThat(ManifestService.isVisibleTo(module("x", "internal"), false)).isFalse();
        assertThat(ManifestService.isVisibleTo(module("x", "internal"), true)).isTrue();
        assertThat(ManifestService.isVisibleTo(module("x", null), false)).isTrue();
        assertThat(ManifestService.isVisibleTo(module("x", "weird"), false)).isTrue();
    }
}
