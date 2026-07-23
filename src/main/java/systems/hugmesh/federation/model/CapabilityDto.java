package systems.hugmesh.federation.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Wire shape returned by the PUBLIC {@code GET /api/federation/capabilities}
 * projection — the install-state list a LOGGED-OUT or non-admin host uses to
 * grey-out OPTIONAL services that are absent / disabled / circuit-broken.
 *
 * <p><b>Why this exists (optional-services design CORRECTION 2).</b> The host
 * CANNOT use {@code GET /api/federation/manifest} for greying-out: that endpoint
 * is {@code authenticated()} (an anonymous browser gets 401) and is
 * visibility-filtered (internal-visibility remotes — forum/mastodon/matrix/games —
 * are stripped for non-admin callers). So an anonymous host could never even learn
 * those slugs exist. This projection is {@code permitAll}: it tells every host
 * which optional services are registered and whether each is currently usable, so
 * the host can render a greyed-out (disabled + helptext) card for a service that is
 * NOT installed rather than a broken/500 one.
 *
 * <p><b>Public-safe by construction.</b> This is a DELIBERATELY NARROW projection
 * of {@link FederationModule}: it carries ONLY {@code slug}, {@code installed},
 * {@code mountAt}, and {@code requiresRole}. It does NOT expose
 * {@code remoteEntryUrl}, {@code exposedModule}, {@code contentHash},
 * {@code ownerUserId}, {@code version}, {@code visibility}, the raw
 * {@code metadata} blob, or any other internal-only locator/detail — those stay on
 * the authed manifest. {@code requiresRole} + {@code mountAt} are the only metadata
 * fields surfaced because the host needs them to label + route the greyed card; the
 * rest of the metadata blob is withheld.
 *
 * <p>{@code installed} = the row exists AND is enabled AND circuit-closed (i.e. the
 * service is actually serveable right now). An OPTIONAL service that was never
 * registered (no row) simply does not appear in the list at all — the host greys it
 * out by absence. A registered-but-disabled / circuit-broken service appears with
 * {@code installed=false} so the host can grey it out by state.
 */
public record CapabilityDto(
        String slug,
        boolean installed,
        String mountAt,
        String requiresRole
) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Project a registry row to its public-safe capability descriptor.
     * {@code installed} is derived from the runtime-serveable state
     * (enabled + circuit-closed); {@code mountAt} / {@code requiresRole} are the
     * ONLY two fields read out of the {@code metadata} JSON blob (the rest of the
     * blob is never surfaced). Null-safe: a missing / unparseable metadata field
     * projects to {@code null}, never an error.
     */
    public static CapabilityDto from(FederationModule m) {
        boolean installed = m.isEnabled() && "closed".equalsIgnoreCase(m.getCircuitState());
        return new CapabilityDto(
                m.getSlug(),
                installed,
                metadataString(m.getMetadata(), "mountAt"),
                metadataString(m.getMetadata(), "requiresRole"));
    }

    /**
     * Null-safe read of a single TOP-LEVEL string field from the module's
     * {@code metadata} JSON. Pure CPU (no blocking I/O — safe on the reactive
     * path). Returns {@code null} when metadata is absent / unparseable / lacks the
     * field, so a malformed metadata blob never breaks the public read path or
     * leaks a non-string node.
     */
    static String metadataString(String metadata, String field) {
        if (metadata == null || metadata.isBlank()) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(metadata);
            JsonNode v = node.get(field);
            return (v != null && v.isTextual()) ? v.asText() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
