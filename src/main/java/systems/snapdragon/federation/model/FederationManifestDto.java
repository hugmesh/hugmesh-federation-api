package systems.snapdragon.federation.model;

import java.util.List;

/**
 * Wire shape returned by {@code GET /api/federation/manifest}.
 *
 * <p>Lifted from the games {@code FederationManifestDto}: the Angular host's
 * bootstrap calls this endpoint, then feeds {@code remotes} into
 * native-federation's {@code initFederation(...)}. The platform variant adds
 * {@code contentHash} so the host (and the remote-fragment pods) can pin /
 * cache-bust by content-addressed version.
 *
 * <p>{@code metadata} stays a JSON-string blob on the wire (the service does not
 * deserialise it; the host does only when it needs a flag).
 */
public record FederationManifestDto(
        String generatedAt,
        List<FederationRemoteDto> remotes
) {
    public record FederationRemoteDto(
            String slug,
            String displayName,
            String kind,
            String remoteEntryUrl,
            String exposedModule,
            String version,
            String contentHash,
            String visibility,
            String metadata
    ) {
        public static FederationRemoteDto from(FederationModule m) {
            return new FederationRemoteDto(
                    m.getSlug(),
                    m.getDisplayName(),
                    m.getKind(),
                    m.getRemoteEntryUrl(),
                    m.getExposedModule(),
                    m.getVersion(),
                    m.getContentHash(),
                    m.getVisibility(),
                    m.getMetadata()
            );
        }
    }
}
