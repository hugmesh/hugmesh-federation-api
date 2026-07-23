package systems.hugmesh.federation.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit coverage for the public capability projection's null-safe metadata reader
 * (package-private {@code metadataString}) and the install-state derivation in
 * {@link CapabilityDto#from}. Lives in the {@code model} package so it can reach the
 * package-private helper directly (mirrors why {@code requiresRole} is tested in
 * the service package in ManifestServiceTest).
 */
class CapabilityDtoTest {

    private static FederationModule module(boolean enabled, String circuit, String metadata) {
        FederationModule m = new FederationModule();
        m.setSlug("svc");
        m.setEnabled(enabled);
        m.setCircuitState(circuit);
        m.setMetadata(metadata);
        return m;
    }

    @Test
    void metadataString_isNullSafe_neverLeaksNonStringNode() {
        // null / blank / malformed / missing-field / non-string-node => null, never
        // an error and never a non-string leak.
        assertThat(CapabilityDto.metadataString(null, "mountAt")).isNull();
        assertThat(CapabilityDto.metadataString("", "mountAt")).isNull();
        assertThat(CapabilityDto.metadataString("   ", "mountAt")).isNull();
        assertThat(CapabilityDto.metadataString("not-json", "mountAt")).isNull();
        assertThat(CapabilityDto.metadataString("{\"mountAt\":42}", "mountAt")).isNull();
        assertThat(CapabilityDto.metadataString("{\"other\":\"x\"}", "mountAt")).isNull();
        assertThat(CapabilityDto.metadataString("{\"mountAt\":\"/games\"}", "mountAt")).isEqualTo("/games");
        assertThat(CapabilityDto.metadataString("{\"requiresRole\":\"ROLE_GAMES\"}", "requiresRole"))
                .isEqualTo("ROLE_GAMES");
    }

    @Test
    void from_derivesInstalled_andSurfacesOnlyMountAtAndRequiresRole() {
        CapabilityDto on = CapabilityDto.from(
                module(true, "closed", "{\"mountAt\":\"/social/forum\",\"requiresRole\":\"forum\"}"));
        assertThat(on.slug()).isEqualTo("svc");
        assertThat(on.installed()).isTrue();
        assertThat(on.mountAt()).isEqualTo("/social/forum");
        assertThat(on.requiresRole()).isEqualTo("forum");

        // disabled OR circuit-open => not installed (case-insensitive circuit check).
        assertThat(CapabilityDto.from(module(false, "closed", "{}")).installed()).isFalse();
        assertThat(CapabilityDto.from(module(true, "open", "{}")).installed()).isFalse();
        assertThat(CapabilityDto.from(module(true, "CLOSED", "{}")).installed()).isTrue();
    }
}
