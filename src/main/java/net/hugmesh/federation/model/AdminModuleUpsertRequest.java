package net.hugmesh.federation.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import net.hugmesh.federation.web.ValidationPatterns;

/**
 * Request body of the SUPERADMIN upsert-by-slug endpoint
 * ({@code POST /api/federation/admin/modules}) — the create-and-federate wizard's
 * module-registration payload.
 *
 * <p>Deliberately a DEDICATED record rather than reusing {@link FederationModule}
 * as the body (the general registry's convention), for two reasons:
 * <ul>
 *   <li><b>the {@code enabled} trap</b> — {@link FederationModule#isEnabled()} is a
 *       primitive {@code boolean}, so a JSON body that omits {@code enabled}
 *       deserialises to {@code false} and an entity-bodied upsert would silently
 *       DISABLE an existing enabled module. Here {@code enabled} is a boxed
 *       {@link Boolean}: {@code null} means "not supplied" — defaulted to
 *       {@code false} on create and LEFT UNCHANGED on a refresh of an existing
 *       row (no-surprise-writes);</li>
 *   <li><b>a narrower vocabulary</b> — the wizard only ever provisions
 *       {@code remote-shell} / {@code fragment} remotes with an ABSOLUTE http(s)
 *       {@code remoteEntryUrl} and a required {@code exposedModule}, so the
 *       field constraints here are tighter than the entity's.</li>
 * </ul>
 *
 * <p>Fields NOT accepted from this body (all stamped server-side or out of scope
 * for the wizard): {@code id}, {@code domain} (always the caller's write domain —
 * {@code "default"} for SUPERADMIN), {@code circuitState} (the kill-switch state
 * belongs exclusively to {@code /api/federation/overrides}; an upsert NEVER
 * closes an open circuit), {@code ownerUserId} (wizard modules are platform
 * modules), {@code contentHash} (bundle-pipeline territory), timestamps.
 *
 * <p>{@code metadata} is the registry's raw-JSON-string convention (see
 * {@link FederationModule#getMetadata()}); its {@code mountAt} /
 * {@code requiresRole} keys are shape-checked in
 * {@link net.hugmesh.federation.service.AdminModuleService} so a
 * first-party console can never write a blob the manifest read path would have
 * to silently swallow.
 *
 * @param slug           unique DNS-label module slug (required; the upsert key)
 * @param displayName    human-readable name; {@code null}/blank keeps the existing
 *                       row's name (or defaults to the slug on create)
 * @param kind           {@code remote-shell | fragment}; {@code null} defaults to
 *                       {@code remote-shell} on create, keeps the existing kind on
 *                       a refresh
 * @param remoteEntryUrl absolute http(s) URL of the remote's entry file (required)
 * @param exposedModule  the federation-exposed module key, e.g. {@code ./routes}
 *                       (required)
 * @param version        module version string; {@code null} defaults to
 *                       {@code 1.0.0} on create, keeps the existing version on a
 *                       refresh
 * @param visibility     {@code public | internal}; {@code null} defaults to
 *                       {@code internal} on create (a freshly-federated service is
 *                       dark until deliberately made public), keeps the existing
 *                       visibility on a refresh
 * @param enabled        whether the module serves in manifests; {@code null}
 *                       defaults to {@code false} on create and leaves an existing
 *                       row's flag UNCHANGED on a refresh
 * @param metadata       raw JSON object string carrying the
 *                       {@code {"mountAt":"/x","requiresRole":"role"}} convention;
 *                       {@code null} keeps the existing metadata
 */
public record AdminModuleUpsertRequest(
        @NotBlank(message = "slug is required")
        @Pattern(regexp = ValidationPatterns.SLUG,
                message = "slug must be a DNS-label-style token (lower-alnum + hyphens, 1-128 chars)")
        String slug,
        @Size(max = 1024, message = "displayName must be at most 1024 chars")
        String displayName,
        @Pattern(regexp = ValidationPatterns.ADMIN_MODULE_KIND,
                message = "kind must be remote-shell|fragment")
        String kind,
        @NotBlank(message = "remoteEntryUrl is required")
        @Pattern(regexp = ValidationPatterns.REMOTE_ENTRY_URL,
                message = "remoteEntryUrl must be an absolute http(s) URL")
        @Size(max = 1024, message = "remoteEntryUrl must be at most 1024 chars")
        String remoteEntryUrl,
        @NotBlank(message = "exposedModule is required")
        @Size(max = 1024, message = "exposedModule must be at most 1024 chars")
        String exposedModule,
        @Size(max = 1024, message = "version must be at most 1024 chars")
        String version,
        @Pattern(regexp = ValidationPatterns.VISIBILITY, message = "visibility must be public|internal")
        String visibility,
        Boolean enabled,
        String metadata) {}
