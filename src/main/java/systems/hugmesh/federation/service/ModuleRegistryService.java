package systems.hugmesh.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.hugmesh.federation.model.FederationModule;
import systems.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Admin write surface for the {@code federation_modules} registry.
 *
 * <h2>Responsibility</h2>
 *
 * <p>This service is the authoritative write path for {@link FederationModule} rows.
 * It provides full CRUD over {@code federation_modules}: registering new Angular
 * micro-frontend remotes, reading the registry for admin inspection, patching module
 * metadata and circuit state, and removing modules from the registry.  Changes made
 * here appear in the next manifest render served by {@code ManifestService} and
 * {@code CapabilityService}, which are the corresponding read surfaces.
 *
 * <p>All mutations enforce domain isolation at the query level: the {@code domain}
 * column is always stamped from the caller's authenticated scope and is never taken
 * from the request body, so a client cannot plant or mutate rows in another brand.
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <p>Only ROLE_ADMIN and ROLE_SUPERADMIN may access the registry write surface.
 * A per-domain admin is restricted to their own brand's rows; ROLE_SUPERADMIN
 * operates across all brands without a domain predicate.
 *
 * <pre>
 *  Role              │ list        │ get         │ create      │ update      │ delete
 *  ──────────────────┼─────────────┼─────────────┼─────────────┼─────────────┼────────────
 *  ROLE_ADMIN        │ own domain  │ own domain  │ own domain  │ own domain  │ own domain
 *  ROLE_SUPERADMIN   │ ALL domains │ ALL domains │ ALL domains │ ALL domains │ ALL domains
 * </pre>
 *
 * <h2>Username-skeleton side-effect on profile fragment create</h2>
 *
 * <p>When a {@code profile-&lt;username&gt;} fragment row is created (the vanity-profile
 * mint), the canonical confusable skeleton for {@code &lt;username&gt;} is written to
 * {@code username_skeleton} in the same reactive flow (via
 * {@link UsernameAvailabilityService#grant}) so the look-alike collision check has
 * its indexed cache row.  The skeleton write is best-effort — a write failure never
 * fails the module create; the slug UNIQUE column and the 017 reserved CHECK are the
 * authoritative exact-username backstop, and the skeleton is fully recomputable.
 *
 * @see systems.hugmesh.federation.controller.ModuleRegistryController
 * @see FederationModuleRepository
 * @see FederationModule
 * @see UsernameAvailabilityService
 * @see VanityService
 * @see PrincipalDomain
 */
@Service
public class ModuleRegistryService {

    /** A profile fragment's slug is {@code profile-<username>} (the vanity convention). */
    static final String PROFILE_SLUG_PREFIX = "profile-";
    static final String FRAGMENT_KIND = "fragment";

    private final FederationModuleRepository repo;
    private final UsernameAvailabilityService usernames;

    public ModuleRegistryService(FederationModuleRepository repo,
                                 UsernameAvailabilityService usernames) {
        this.repo = repo;
        this.usernames = usernames;
    }

    // ----- Registry Read -----

    /**
     * Returns all module registry rows in scope.
     *
     * <p>A per-domain admin sees ONLY their own brand's modules (via
     * {@code findByDomain}); ROLE_SUPERADMIN sees every registry row across all
     * brands (via {@code findAll}).  The domain cut is enforced in the DB query,
     * not in application code.
     *
     * @param scope the caller's resolved tenant scope; {@code scope.superadmin()}
     *              selects the un-pinned all-brands finder
     * @return a {@code Flux} streaming all {@link FederationModule} rows in scope;
     *         empty when none are registered
     * @see FederationModuleRepository#findAll()
     * @see FederationModuleRepository#findByDomain(String)
     */
    public Flux<FederationModule> list(PrincipalDomain scope) {
        return scope.superadmin() ? repo.findAll() : repo.findByDomain(scope.domain());
    }

    /**
     * Looks up a single module by slug, domain-pinned to the caller's brand.
     *
     * <p>A per-domain admin can only read a module in their own domain — a slug
     * owned by another brand is never surfaced and resolves to a 404.
     * ROLE_SUPERADMIN reads any slug regardless of domain.
     *
     * @param slug  the unique module slug to look up
     * @param scope the caller's resolved tenant scope, used to pin the lookup to
     *              the correct brand
     * @return a {@code Mono} emitting the matching {@link FederationModule}
     * @throws ResponseStatusException with status {@code 404 NOT_FOUND} when no
     *                                 module with the given slug exists in scope, or
     *                                 when it belongs to another brand
     * @see FederationModuleRepository#findBySlug(String)
     * @see FederationModuleRepository#findBySlugAndDomain(String, String)
     */
    public Mono<FederationModule> get(String slug, PrincipalDomain scope) {
        Mono<FederationModule> found = scope.superadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found.switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)));
    }

    // ----- Registry Write -----

    /**
     * Registers a new module in the caller's domain, applying default field values
     * before persisting.
     *
     * <p>The {@code id} field is cleared (forcing an insert), {@code visibility}
     * defaults to {@code "public"}, and {@code circuitState} defaults to
     * {@code "closed"} when not supplied.  The {@code domain} column is overwritten
     * from the caller's authenticated scope — never trusted from the request body —
     * so a client cannot plant a row in another brand's domain.  A ROLE_SUPERADMIN
     * create (no brand in scope) defaults the row to {@code "default"}.
     *
     * <p><b>Profile-fragment side-effect</b>: when the new module is a
     * {@code fragment} kind with a slug matching {@code profile-&lt;username&gt;}, the
     * {@code username_skeleton} cache row for {@code &lt;username&gt;} is minted
     * immediately after the save via {@link #mintSkeletonIfProfile}.  See the
     * class-level Javadoc for the best-effort contract.
     *
     * @param m     the module to register; {@code id} and {@code domain} are
     *              overwritten regardless of the value supplied in the request body
     * @param scope the caller's resolved tenant scope, used to stamp {@code domain}
     *              and both timestamp fields on the new row
     * @return a {@code Mono} emitting the saved {@link FederationModule} with
     *         defaults applied and {@code createdAt} / {@code updatedAt} set to
     *         the current instant
     * @see #mintSkeletonIfProfile(FederationModule)
     * @see UsernameAvailabilityService#grant
     */
    public Mono<FederationModule> create(FederationModule m, PrincipalDomain scope) {
        Instant now = Instant.now();
        m.setId(null);
        if (m.getVisibility() == null) m.setVisibility("public");
        if (m.getCircuitState() == null) m.setCircuitState("closed");
        m.setDomain(domainForWrite(scope));
        m.setCreatedAt(now);
        m.setUpdatedAt(now);
        return repo.save(m).flatMap(saved -> mintSkeletonIfProfile(saved).thenReturn(saved));
    }

    /**
     * Applies a partial update to an existing module, domain-pinned to the caller's
     * brand.
     *
     * <p>The existing row is loaded via the domain-scoped finder so a per-domain
     * admin can never patch a module in another brand — a cross-domain slug resolves
     * to empty and surfaces as a 404.  ROLE_SUPERADMIN may update any slug.
     *
     * <p>Non-null patch fields applied: {@code displayName}, {@code kind},
     * {@code remoteEntryUrl}, {@code exposedModule}, {@code version},
     * {@code contentHash}, {@code visibility}, {@code circuitState}, {@code metadata}.
     * The {@code enabled} flag is always applied from the patch (no null guard).
     * The {@code domain} column is intentionally NOT patchable — a row remains in
     * its original brand after update.
     *
     * @param slug  the unique slug of the module to update
     * @param patch a {@link FederationModule} carrying the fields to apply; only
     *              non-null fields are merged (except {@code enabled}, which is
     *              always taken from the patch); {@code domain} is ignored
     * @param scope the caller's resolved tenant scope, used to pin the load to the
     *              correct brand
     * @return a {@code Mono} emitting the updated {@link FederationModule} with
     *         {@code updatedAt} refreshed to the current instant
     * @throws ResponseStatusException with status {@code 404 NOT_FOUND} when no
     *                                 module with the given slug exists in scope, or
     *                                 when it belongs to another brand
     */
    public Mono<FederationModule> update(String slug, FederationModule patch, PrincipalDomain scope) {
        Mono<FederationModule> found = scope.superadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                // Merge non-null patch fields into the existing row and persist the result.
                .flatMap(existing -> repo.save(applyPatch(existing, patch)));
    }

    /**
     * Merges all non-null fields from {@code patch} into {@code existing}; the domain
     * field is intentionally excluded — a row always stays in its original brand.
     */
    private static FederationModule applyPatch(FederationModule existing, FederationModule patch) {
        if (patch.getDisplayName() != null) existing.setDisplayName(patch.getDisplayName());
        if (patch.getKind() != null) existing.setKind(patch.getKind());
        if (patch.getRemoteEntryUrl() != null) existing.setRemoteEntryUrl(patch.getRemoteEntryUrl());
        if (patch.getExposedModule() != null) existing.setExposedModule(patch.getExposedModule());
        if (patch.getVersion() != null) existing.setVersion(patch.getVersion());
        if (patch.getContentHash() != null) existing.setContentHash(patch.getContentHash());
        if (patch.getVisibility() != null) existing.setVisibility(patch.getVisibility());
        if (patch.getCircuitState() != null) existing.setCircuitState(patch.getCircuitState());
        if (patch.getMetadata() != null) existing.setMetadata(patch.getMetadata());
        existing.setEnabled(patch.isEnabled());
        existing.setUpdatedAt(Instant.now());
        return existing;
    }

    /**
     * Removes a module from the registry, domain-pinned to the caller's brand.
     *
     * <p>The existing row is loaded via the domain-scoped finder so a per-domain
     * admin can never delete another brand's module — a cross-domain slug resolves
     * to empty and surfaces as a 404.  ROLE_SUPERADMIN may delete any slug.
     *
     * @param slug  the unique slug of the module to delete
     * @param scope the caller's resolved tenant scope, used to pin the load to the
     *              correct brand
     * @return a {@code Mono<Void>} that completes empty on successful deletion
     * @throws ResponseStatusException with status {@code 404 NOT_FOUND} when no
     *                                 module with the given slug exists in scope, or
     *                                 when it belongs to another brand
     */
    public Mono<Void> delete(String slug, PrincipalDomain scope) {
        Mono<FederationModule> found = scope.superadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                .flatMap(repo::delete);
    }

    // ----- Helpers -----

    /**
     * Resolves the domain to stamp on a written module row.
     *
     * <p>For a per-domain principal the value is taken from the authenticated scope
     * (never from the request body).  For a ROLE_SUPERADMIN write (no brand in
     * scope) the row lands in {@code "default"}.
     *
     * @param scope the caller's resolved tenant scope
     * @return the domain string to write into the {@code domain} column
     */
    private static String domainForWrite(PrincipalDomain scope) {
        return scope.superadmin() ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    /**
     * Mints the {@code username_skeleton} cache row for a newly created
     * {@code profile-&lt;username&gt;} fragment module.
     *
     * <p>The mint is skipped entirely (returns {@code Mono.empty()}) when the saved
     * module is not a {@code fragment} kind or its slug does not start with
     * {@link #PROFILE_SLUG_PREFIX}.  When the conditions are met, the username is
     * extracted from the slug suffix and passed to
     * {@link UsernameAvailabilityService#grant}; any grant error is swallowed via
     * {@code onErrorResume} so a skeleton-write failure never propagates to the
     * caller.
     *
     * @param saved the module row that was just persisted by {@link #create}
     * @return a {@code Mono<Void>} that completes empty once the skeleton is minted
     *         (or immediately when there is nothing to mint, or when the grant
     *         fails — best-effort)
     */
    private Mono<Void> mintSkeletonIfProfile(FederationModule saved) {
        String slug = saved.getSlug();
        if (slug == null
                || !FRAGMENT_KIND.equalsIgnoreCase(saved.getKind())
                || !slug.startsWith(PROFILE_SLUG_PREFIX)) {
            return Mono.empty();
        }
        String username = slug.substring(PROFILE_SLUG_PREFIX.length());
        return usernames.grant(username, saved.getOwnerUserId())
                .onErrorResume(e -> Mono.empty())
                .then();
    }
}
