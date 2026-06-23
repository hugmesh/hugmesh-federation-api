package systems.snapdragon.federation.model;

/**
 * Wire shape returned by {@code GET /api/federation/vanity/{username}} — the
 * PUBLIC profile-fragment descriptor a vanity host
 * ({@code <username>.snapdragon.systems}) needs to load + render the user's
 * public profile fragment.
 *
 * <p>This is a NARROW projection of {@link FederationModule}: it carries ONLY the
 * locator + content-addressed version the host / remote-fragment fleet need, and
 * is ONLY ever built from a {@code kind='fragment'}, {@code visibility='public'},
 * enabled + circuit-closed module (the resolve query + service guard enforce
 * that). It deliberately does NOT expose {@code ownerUserId}, {@code enabled},
 * {@code circuitState}, or any internal-only field — the vanity endpoint is a
 * public read (no JWT), so the wire body stays public-safe by construction.
 *
 * <p>{@code fragmentPath} is the gateway-relative static path the
 * snapdragon-remote-fragment fleet serves the bundle at
 * ({@code /_fragments/<slug>/<contentHash>/}); the host's {@code loadRemoteModule}
 * fetches {@code remoteEntry.json} under it. It is derived here (slug + hash) so
 * the caller does not have to reconstruct the convention.
 */
public record VanityProfileDto(
        String username,
        String slug,
        String displayName,
        String kind,
        String remoteEntryUrl,
        String exposedModule,
        String version,
        String contentHash,
        String visibility,
        String fragmentPath,
        String metadata
) {
    /**
     * Build the descriptor for a resolved username + its public profile-fragment
     * module. {@code fragmentPath} is the content-addressed static prefix the
     * remote-fragment fleet serves; null when there is no content hash yet (the
     * bundle has not been synced/published), so the host can distinguish "module
     * registered but no bytes" from "served".
     */
    public static VanityProfileDto from(final String username, final FederationModule m) {
        String path = (m.getContentHash() == null || m.getContentHash().isBlank())
                ? null
                : "/_fragments/" + m.getSlug() + "/" + m.getContentHash() + "/";
        return new VanityProfileDto(
                username,
                m.getSlug(),
                m.getDisplayName(),
                m.getKind(),
                m.getRemoteEntryUrl(),
                m.getExposedModule(),
                m.getVersion(),
                m.getContentHash(),
                m.getVisibility(),
                path,
                m.getMetadata()
        );
    }
}
