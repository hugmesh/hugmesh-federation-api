package systems.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;
import systems.hugmesh.federation.model.CapabilityDto;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.repository.FederationModuleRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit coverage for the PUBLIC capability projection: the install-state derivation
 * (enabled + circuit-closed), the narrow public-safe shape (slug + installed +
 * mountAt + requiresRole ONLY — no internal locator/detail), the slug ordering, and
 * the null-safe metadata reads. The repository is mocked; assertions are reactive.
 */
class CapabilityServiceTest {

    private static FederationModule module(String slug, boolean enabled, String circuit, String metadata) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setDisplayName(slug + " display");
        m.setKind("remote-shell");
        m.setRemoteEntryUrl("http://" + slug + ":8080/remoteEntry.json");
        m.setExposedModule("./routes");
        m.setOwnerUserId("secret-owner");
        m.setVersion("9.9.9");
        m.setContentHash("deadbeef");
        m.setVisibility("internal");
        m.setEnabled(enabled);
        m.setCircuitState(circuit);
        m.setMetadata(metadata);
        return m;
    }

    private static FederationModuleRepository repoOf(FederationModule... rows) {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        // The PUBLIC projection now uses the DOMAIN-pinned, fragment-excluding finder
        // (cross-tenant disclosure fix) — NOT the inherited unscoped findAll(). These
        // rows have no explicit domain set (entity default "default"), so a default-
        // domain caller sees them; the projection-shape assertions are unchanged.
        when(repo.findByDomainAndKindNot("default", "fragment")).thenReturn(Flux.just(rows));
        return repo;
    }

    @Test
    void installed_isTrue_onlyWhenEnabledAndCircuitClosed() {
        FederationModuleRepository repo = repoOf(
                module("a-on",   true,  "closed", "{\"mountAt\":\"/social/a\",\"requiresRole\":\"a\"}"),
                module("b-off",  false, "closed", "{\"mountAt\":\"/social/b\",\"requiresRole\":\"b\"}"),
                module("c-broke", true, "open",   "{\"mountAt\":\"/social/c\",\"requiresRole\":\"c\"}"));

        List<CapabilityDto> caps = new CapabilityService(repo).capabilities().collectList().block();

        assertThat(caps).extracting(CapabilityDto::slug)
                .containsExactly("a-on", "b-off", "c-broke"); // slug-ordered
        assertThat(caps).filteredOn(c -> c.slug().equals("a-on"))
                .singleElement().extracting(CapabilityDto::installed).isEqualTo(true);
        // disabled => installed=false (registered-but-disabled, host greys by state).
        assertThat(caps).filteredOn(c -> c.slug().equals("b-off"))
                .singleElement().extracting(CapabilityDto::installed).isEqualTo(false);
        // circuit-open => installed=false (kill-switched, host greys by state).
        assertThat(caps).filteredOn(c -> c.slug().equals("c-broke"))
                .singleElement().extracting(CapabilityDto::installed).isEqualTo(false);
    }

    @Test
    void projection_surfacesOnlyMountAtAndRequiresRole_fromMetadata() {
        FederationModuleRepository repo = repoOf(
                module("mastodon", true, "closed",
                        "{\"requiresRole\":\"mastodon\",\"mountAt\":\"/social/mastodon\"}"));

        CapabilityDto cap = new CapabilityService(repo).capabilities().blockFirst();

        assertThat(cap.slug()).isEqualTo("mastodon");
        assertThat(cap.installed()).isTrue();
        assertThat(cap.mountAt()).isEqualTo("/social/mastodon");
        assertThat(cap.requiresRole()).isEqualTo("mastodon");
    }

    @Test
    void dto_hasNoInternalOnlyAccessors() {
        // The public-safe shape is exactly {slug, installed, mountAt, requiresRole}.
        // A compile-time guard: the record exposes ONLY those four components, so an
        // internal field (remoteEntryUrl, ownerUserId, contentHash, version,
        // visibility, raw metadata) can never leak through this projection.
        var components = CapabilityDto.class.getRecordComponents();
        assertThat(components).extracting(java.lang.reflect.RecordComponent::getName)
                .containsExactly("slug", "installed", "mountAt", "requiresRole");
    }

    @Test
    void malformedMetadata_yieldsNullFields_neverErrors() {
        // A row whose metadata is unparseable still projects cleanly: installed is
        // derived from enabled+circuit (not metadata), and mountAt/requiresRole come
        // back null rather than breaking the public read path. (The field-level
        // null-safety of the metadata reader is unit-tested in CapabilityDtoTest.)
        FederationModuleRepository repo = repoOf(module("broken", true, "closed", "not-json"));

        CapabilityDto cap = new CapabilityService(repo).capabilities().blockFirst();

        assertThat(cap.slug()).isEqualTo("broken");
        assertThat(cap.installed()).isTrue();
        assertThat(cap.mountAt()).isNull();
        assertThat(cap.requiresRole()).isNull();
    }

    @Test
    void emptyRegistry_yieldsEmptyList_noError() {
        FederationModuleRepository repo = mock(FederationModuleRepository.class);
        when(repo.findByDomainAndKindNot("default", "fragment")).thenReturn(Flux.empty());

        StepVerifier.create(new CapabilityService(repo).capabilities())
                .verifyComplete();
    }
}
