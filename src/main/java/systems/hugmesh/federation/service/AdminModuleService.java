package systems.hugmesh.federation.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.model.AdminModuleUpsertRequest;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.repository.FederationModuleRepository;
import systems.hugmesh.federation.web.ValidationPatterns;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Locale;
import java.util.regex.Pattern;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * SUPERADMIN-only write surface for the {@code federation_modules} registry —
 * the federation-api half of the create-and-federate wizard
 * ({@code /api/federation/admin/modules}).
 *
 * <h2>Responsibility</h2>
 *
 * <p>Three operations, all cross-domain (the caller is always the SUPERADMIN
 * control plane — see {@link systems.hugmesh.federation.controller.AdminModuleController}):
 * <ul>
 *   <li>{@link #list} — the FULL registry state (every brand, including disabled,
 *       circuit-open and internal rows — the admin view, not the manifest-filtered
 *       public view);</li>
 *   <li>{@link #upsert} — idempotent upsert-by-slug: create when the slug is
 *       absent, refresh-in-place when present. The wizard (admin-bff's
 *       {@code RestFederationModuleClient}) re-POSTs the same slug on every
 *       federate action, so the write must be re-runnable;</li>
 *   <li>{@link #softDisable} — {@code enabled=false}, NEVER a hard delete: the row
 *       stays in the registry for inspection + re-enable (a later upsert with
 *       {@code enabled=true}). The hard delete remains exclusively
 *       {@code DELETE /api/federation/modules/{slug}}.</li>
 * </ul>
 *
 * <h2>Manifest-invariant preservation (why every guard exists)</h2>
 *
 * <p>{@link ManifestService} assumes every {@code federation_modules} row honours
 * a set of invariants; this service enforces the SAME rules on write so an
 * admin-provisioned row can never degrade the read path:
 * <ul>
 *   <li><b>slug vocabulary</b> — {@code profile-*} slugs belong EXCLUSIVELY to the
 *       vanity publish path ({@link VanityPublishService}); an admin upsert of one
 *       is rejected 400 up front. This is a superset of (and therefore always
 *       fail-safes before) the DB's {@code ck_fed_modules_reserved_profile_slug}
 *       CHECK, which would otherwise surface as a raw 500;</li>
 *   <li><b>remoteEntryUrl</b> — must be an absolute http(s) URL (re-parsed here
 *       with {@link URI} on top of the bean-validation pattern, defence-in-depth),
 *       so the host shell never receives an unloadable entry locator;</li>
 *   <li><b>metadata</b> — must be a JSON OBJECT string whose {@code mountAt} /
 *       {@code requiresRole} keys (when present) match the platform shapes
 *       ({@link ValidationPatterns#METADATA_MOUNT_AT} /
 *       {@link ValidationPatterns#METADATA_REQUIRES_ROLE}). The read path
 *       tolerates malformed metadata ({@code ManifestService.requiresRole}
 *       swallows parse failures), but a first-party console must never WRITE a
 *       blob the read path would have to swallow — a bad {@code requiresRole}
 *       would silently detach the module from {@code scope=role} kill-switches;</li>
 *   <li><b>kill-switch interplay</b> — {@code circuitState} is NEVER touched by an
 *       upsert (create defaults it to {@code closed}); a circuit-break kill on an
 *       existing row therefore SURVIVES any number of wizard re-POSTs and can only
 *       be lifted via {@code POST /api/federation/overrides/{slug}/rearm}.
 *       Deliberately re-setting {@code enabled=true} on a row an admin unpublish
 *       had disabled IS allowed here — unlike the self-service vanity republish
 *       (409, see {@link VanityPublishService}), this caller IS the top admin role
 *       the rearm endpoint itself gates on;</li>
 *   <li><b>domain</b> — never accepted from the body; a SUPERADMIN write lands in
 *       {@code "default"} (the {@link ModuleRegistryService} convention) and a
 *       refresh never moves an existing row's brand.</li>
 * </ul>
 *
 * <h2>Raced create</h2>
 *
 * <p>Upsert-by-slug is find-then-save, so two concurrent first-time POSTs of the
 * same slug can race the {@code slug} UNIQUE index. The loser's
 * {@link DuplicateKeyException} is caught ONCE and replayed as a refresh of the
 * row the winner inserted — the endpoint stays idempotent instead of surfacing a
 * spurious 500 (the registry has no global DataIntegrity→409 mapper).
 *
 * @see systems.hugmesh.federation.controller.AdminModuleController
 * @see ModuleRegistryService
 * @see ManifestService
 * @see FederationModuleRepository
 */
@Service
public class AdminModuleService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern MOUNT_AT = Pattern.compile(ValidationPatterns.METADATA_MOUNT_AT);
    private static final Pattern REQUIRES_ROLE = Pattern.compile(ValidationPatterns.METADATA_REQUIRES_ROLE);

    /** Wizard-provisioned modules default to the routed remote-shell kind. */
    static final String DEFAULT_KIND = "remote-shell";
    /** A freshly-federated service is dark (admin-only) until deliberately made public. */
    static final String DEFAULT_VISIBILITY = "internal";
    /** Placeholder version when the wizard supplies none (mirrors {@code VanityPublishService}). */
    static final String DEFAULT_VERSION = "1.0.0";

    private final FederationModuleRepository repo;

    public AdminModuleService(FederationModuleRepository repo) {
        this.repo = repo;
    }

    // ----- Read -----

    /**
     * Returns the FULL registry state — every row in every brand, INCLUDING
     * disabled, circuit-open and internal rows (the wizard needs to see what is
     * registered-but-dark, which the manifest read path deliberately hides).
     *
     * @param scope the caller's resolved tenant scope; SUPERADMIN (the only role
     *              the path + method gates admit) reads un-pinned. The per-domain
     *              branch is defence-in-depth only — were the gates ever widened,
     *              a per-brand caller would still be pinned to their own brand
     * @return a {@code Flux} streaming all {@link FederationModule} rows in scope
     */
    public Flux<FederationModule> list(PrincipalDomain scope) {
        return scope.superadmin() ? repo.findAll() : repo.findByDomain(scope.domain());
    }

    // ----- Upsert -----

    /**
     * Idempotent upsert-by-slug: creates the module when the slug is absent,
     * refreshes it in place when present.
     *
     * <p><b>Create defaults</b>: {@code kind=remote-shell},
     * {@code visibility=internal}, {@code enabled=false},
     * {@code circuitState=closed}, {@code displayName=slug},
     * {@code version=1.0.0}, {@code domain} stamped from the caller's scope
     * ({@code "default"} for SUPERADMIN), both timestamps set now.
     *
     * <p><b>Refresh semantics</b>: {@code remoteEntryUrl} + {@code exposedModule}
     * (required in every body) are always applied; {@code displayName},
     * {@code kind}, {@code version}, {@code visibility}, {@code enabled} and
     * {@code metadata} are applied ONLY when supplied (a {@code null} field leaves
     * the existing value untouched — including {@code enabled}, see
     * {@link AdminModuleUpsertRequest}); {@code id}, {@code slug}, {@code domain},
     * {@code circuitState}, {@code ownerUserId}, {@code contentHash} and
     * {@code createdAt} are never modified.
     *
     * @param req   the validated upsert payload
     * @param scope the caller's resolved tenant scope, used only to stamp
     *              {@code domain} on a first-time create
     * @return a {@code Mono} emitting the persisted row (created or refreshed)
     * @throws ResponseStatusException with {@code 400 BAD_REQUEST} when the slug is
     *                                 a reserved {@code profile-*} vanity slug, the
     *                                 {@code remoteEntryUrl} is not an absolute
     *                                 http(s) URL, or the {@code metadata} blob is
     *                                 not a JSON object with well-shaped
     *                                 {@code mountAt} / {@code requiresRole} keys
     */
    public Mono<FederationModule> upsert(AdminModuleUpsertRequest req, PrincipalDomain scope) {
        ResponseStatusException violation = writeGuard(req);
        if (violation != null) {
            return Mono.error(violation);
        }
        return repo.findBySlug(req.slug())
                .flatMap(existing -> repo.save(applyUpsert(existing, req)))
                .switchIfEmpty(Mono.defer(() -> repo.save(newModule(req, scope))
                        // Raced first-time create: the slug UNIQUE index rejected the
                        // loser's INSERT. Replay ONCE as a refresh of the winner's row
                        // so the upsert stays idempotent instead of 500ing.
                        .onErrorResume(DuplicateKeyException.class, raced -> repo
                                .findBySlug(req.slug())
                                .flatMap(existing -> repo.save(applyUpsert(existing, req))))));
    }

    // ----- Soft-disable -----

    /**
     * Soft-disables a module: {@code enabled=false} + {@code updatedAt} refresh,
     * NEVER a hard delete. The very next manifest render drops the row DB-side
     * (the {@code findAllByEnabledTrue...} finders), while {@link #list} keeps it
     * visible for inspection and a later re-enabling upsert. {@code visibility}
     * and {@code circuitState} are left untouched — this is the reversible
     * registry off-switch, not the vanity unpublish (which also flips visibility)
     * nor the circuit-break kill.
     *
     * @param slug  the slug to disable
     * @param scope the caller's resolved tenant scope; SUPERADMIN (the only
     *              admitted role) resolves the slug across all brands
     * @return a {@code Mono<Void>} completing once the row is disabled
     * @throws ResponseStatusException with {@code 404 NOT_FOUND} ({@code "no
     *                                 module: <slug>"}) when no such slug exists
     */
    public Mono<Void> softDisable(String slug, PrincipalDomain scope) {
        Mono<FederationModule> found = scope.superadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                .flatMap(module -> {
                    module.setEnabled(false);
                    module.setUpdatedAt(Instant.now());
                    return repo.save(module);
                })
                .then();
    }

    // ----- Guards -----

    /**
     * The service-side write guard (defence-in-depth on top of the DTO's bean
     * validation): reserved-slug, remoteEntryUrl and metadata checks. Returns the
     * violation to raise, or {@code null} when the payload is clean.
     */
    private static ResponseStatusException writeGuard(AdminModuleUpsertRequest req) {
        if (req.slug() != null
                && req.slug().toLowerCase(Locale.ROOT).startsWith(ModuleRegistryService.PROFILE_SLUG_PREFIX)) {
            return new ResponseStatusException(BAD_REQUEST,
                    "slug '" + req.slug() + "' uses the reserved profile- prefix — profile fragments "
                            + "are published exclusively via PUT /api/federation/vanity/{username}");
        }
        ResponseStatusException url = urlGuard(req.remoteEntryUrl());
        if (url != null) {
            return url;
        }
        return metadataGuard(req.metadata());
    }

    /** Re-parses {@code remoteEntryUrl} as a real {@link URI}: http(s) scheme + a
     *  non-empty authority, or 400. */
    private static ResponseStatusException urlGuard(String remoteEntryUrl) {
        if (remoteEntryUrl == null) {
            return null; // required-ness is the DTO's @NotBlank concern
        }
        try {
            URI uri = new URI(remoteEntryUrl);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            boolean http = "http".equals(scheme) || "https".equals(scheme);
            // getAuthority (not getHost): docker-compose service hostnames may carry
            // underscores, which java.net.URI refuses to surface as a host.
            if (!http || uri.getAuthority() == null || uri.getAuthority().isBlank()) {
                return new ResponseStatusException(BAD_REQUEST,
                        "remoteEntryUrl must be an absolute http(s) URL with a host");
            }
        } catch (URISyntaxException e) {
            return new ResponseStatusException(BAD_REQUEST,
                    "remoteEntryUrl is not a parseable URL: " + e.getReason());
        }
        return null;
    }

    /**
     * {@code metadata}, when supplied, must be a JSON OBJECT string whose
     * {@code mountAt} / {@code requiresRole} keys (when present) are textual and
     * match the platform shapes. Other keys pass through untouched — metadata is
     * free-form by contract; only the two keys the platform ACTS on are pinned.
     */
    private static ResponseStatusException metadataGuard(String metadata) {
        if (metadata == null) {
            return null;
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(metadata);
        } catch (Exception e) {
            return new ResponseStatusException(BAD_REQUEST, "metadata must be a valid JSON string");
        }
        if (node == null || !node.isObject()) {
            return new ResponseStatusException(BAD_REQUEST, "metadata must be a JSON object");
        }
        JsonNode mountAt = node.get("mountAt");
        if (mountAt != null && (!mountAt.isTextual() || !MOUNT_AT.matcher(mountAt.asText()).matches())) {
            return new ResponseStatusException(BAD_REQUEST,
                    "metadata.mountAt must be an absolute mount path (/<segments>, "
                            + "alnum + / _ - only)");
        }
        JsonNode requiresRole = node.get("requiresRole");
        if (requiresRole != null
                && (!requiresRole.isTextual() || !REQUIRES_ROLE.matcher(requiresRole.asText()).matches())) {
            return new ResponseStatusException(BAD_REQUEST,
                    "metadata.requiresRole must be a bare role name (1-32 alnum/_/- chars, "
                            + "no ROLE_ prefix)");
        }
        return null;
    }

    // ----- Upsert helpers -----

    /** First-time create: apply the admin-surface defaults + server-side stamps. */
    private static FederationModule newModule(AdminModuleUpsertRequest req, PrincipalDomain scope) {
        Instant now = Instant.now();
        FederationModule m = new FederationModule();
        m.setSlug(req.slug());
        m.setDisplayName(orDefault(req.displayName(), req.slug()));
        m.setKind(orDefault(req.kind(), DEFAULT_KIND));
        m.setRemoteEntryUrl(req.remoteEntryUrl());
        m.setExposedModule(req.exposedModule());
        m.setVersion(orDefault(req.version(), DEFAULT_VERSION));
        m.setVisibility(orDefault(req.visibility(), DEFAULT_VISIBILITY));
        m.setEnabled(Boolean.TRUE.equals(req.enabled()));
        m.setCircuitState("closed");
        m.setMetadata(req.metadata());
        m.setDomain(domainForWrite(scope));
        m.setCreatedAt(now);
        m.setUpdatedAt(now);
        return m;
    }

    /**
     * Refresh-in-place: required fields always applied, optional fields only when
     * supplied; {@code slug}/{@code domain}/{@code circuitState}/{@code createdAt}
     * (and the bundle-pipeline fields) never move.
     */
    private static FederationModule applyUpsert(FederationModule existing, AdminModuleUpsertRequest req) {
        if (req.displayName() != null && !req.displayName().isBlank()) {
            existing.setDisplayName(req.displayName());
        }
        if (req.kind() != null) {
            existing.setKind(req.kind());
        }
        existing.setRemoteEntryUrl(req.remoteEntryUrl());
        existing.setExposedModule(req.exposedModule());
        if (req.version() != null) {
            existing.setVersion(req.version());
        }
        if (req.visibility() != null) {
            existing.setVisibility(req.visibility());
        }
        if (req.enabled() != null) {
            existing.setEnabled(req.enabled());
        }
        if (req.metadata() != null) {
            existing.setMetadata(req.metadata());
        }
        existing.setUpdatedAt(Instant.now());
        return existing;
    }

    private static String orDefault(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }

    /** SUPERADMIN writes land in {@code "default"} — the {@link ModuleRegistryService}
     *  convention; a per-domain scope (unreachable through the gates today) would
     *  stamp its own brand. */
    private static String domainForWrite(PrincipalDomain scope) {
        return (scope != null && !scope.superadmin()) ? scope.domain() : "default";
    }
}
