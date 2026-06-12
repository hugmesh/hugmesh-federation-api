package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.security.DomainScope;

import java.time.Instant;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Registry CRUD for {@code federation_modules} — the admin-bff / owner-client
 * write surface. Reactive (Mono/Flux) throughout; sets the timestamp +
 * default-state fields on create the same way the games upload path inserts a
 * federation_modules row.
 *
 * <p><b>Username-skeleton wiring.</b> When a {@code profile-<username>} fragment
 * row is created (the vanity-profile mint), the canonical confusable skeleton for
 * {@code <username>} is written to {@code username_skeleton} IN THE SAME FLOW (via
 * {@link UsernameAvailabilityService#grant}) so the look-alike collision check has
 * its indexed cache row. The skeleton write is best-effort relative to the module
 * create — the slug UNIQUE column + the 017 reserved CHECK remain the authoritative
 * exact-username backstop; the skeleton is a recomputable cache, never a gate that
 * can fail the create.
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

    /**
     * DOMAIN-scoped registry list. A per-domain admin sees ONLY their own brand's
     * modules ({@code findByDomain}); SUPERADMIN sees every registry row across all
     * brands ({@code findAll}). The per-domain CUT is enforced in the QUERY, not in
     * (spoofable) code.
     */
    public Flux<FederationModule> list(DomainScope scope) {
        return scope.isSuperadmin() ? repo.findAll() : repo.findByDomain(scope.domain());
    }

    /**
     * DOMAIN-scoped slug lookup. A per-domain admin can only read a module IN THEIR
     * OWN domain — a slug owned by another brand returns 404 (the cross-domain row is
     * never surfaced). SUPERADMIN reads any slug.
     */
    public Mono<FederationModule> get(String slug, DomainScope scope) {
        Mono<FederationModule> found = scope.isSuperadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found.switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)));
    }

    /**
     * Create a module IN THE PRINCIPAL'S DOMAIN. The {@code domain} column is
     * OVERWRITTEN from the authenticated scope (never trusted from the request body)
     * so a client cannot plant a row in another brand's domain. A SUPERADMIN create
     * (no domain in scope) defaults the row to {@code "default"} — superadmin
     * provisioning of cross-brand rows is a later admin-tooling concern; the
     * foundation never lets a write land cross-domain by accident.
     */
    public Mono<FederationModule> create(FederationModule m, DomainScope scope) {
        Instant now = Instant.now();
        m.setId(null);
        if (m.getVisibility() == null) m.setVisibility("public");
        if (m.getCircuitState() == null) m.setCircuitState("closed");
        m.setDomain(domainForWrite(scope));
        m.setCreatedAt(now);
        m.setUpdatedAt(now);
        return repo.save(m).flatMap(saved -> mintSkeletonIfProfile(saved).thenReturn(saved));
    }

    /** The domain to stamp on a written row: the principal's domain, or
     *  {@code "default"} for a SUPERADMIN write (no domain in scope). NEVER taken
     *  from the request body. */
    private static String domainForWrite(DomainScope scope) {
        return scope.isSuperadmin() ? DomainScope.of("default").domain() : scope.domain();
    }

    /**
     * If the saved row is a {@code profile-<username>} fragment, mint the
     * {@code username_skeleton} cache row for {@code <username>} in the same flow.
     * Best-effort: a skeleton-write failure never fails the module create (the slug
     * UNIQUE column + 017 CHECK are the authoritative backstop, and the skeleton is
     * fully recomputable), so the grant errors are swallowed.
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

    /**
     * DOMAIN-scoped partial update. The existing row is loaded pinned to the
     * principal's domain, so a per-domain admin can NEVER patch a module in another
     * brand (a cross-domain slug returns 404). The {@code domain} column is NOT
     * patchable — it is left as the loaded row's value, so an update can never
     * re-home a row into another brand. SUPERADMIN updates any slug.
     */
    public Mono<FederationModule> update(String slug, FederationModule patch, DomainScope scope) {
        Mono<FederationModule> found = scope.isSuperadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                .flatMap(existing -> {
                    if (patch.getDisplayName() != null) existing.setDisplayName(patch.getDisplayName());
                    if (patch.getKind() != null) existing.setKind(patch.getKind());
                    if (patch.getRemoteEntryUrl() != null) existing.setRemoteEntryUrl(patch.getRemoteEntryUrl());
                    if (patch.getExposedModule() != null) existing.setExposedModule(patch.getExposedModule());
                    if (patch.getVersion() != null) existing.setVersion(patch.getVersion());
                    if (patch.getContentHash() != null) existing.setContentHash(patch.getContentHash());
                    if (patch.getVisibility() != null) existing.setVisibility(patch.getVisibility());
                    if (patch.getCircuitState() != null) existing.setCircuitState(patch.getCircuitState());
                    if (patch.getMetadata() != null) existing.setMetadata(patch.getMetadata());
                    // domain is intentionally NOT patchable — a row stays in its brand.
                    existing.setEnabled(patch.isEnabled());
                    existing.setUpdatedAt(Instant.now());
                    return repo.save(existing);
                });
    }

    /**
     * DOMAIN-scoped delete. Loaded pinned to the principal's domain so a per-domain
     * admin can NEVER delete another brand's module (cross-domain slug -> 404).
     * SUPERADMIN deletes any slug.
     */
    public Mono<Void> delete(String slug, DomainScope scope) {
        Mono<FederationModule> found = scope.isSuperadmin()
                ? repo.findBySlug(slug)
                : repo.findBySlugAndDomain(slug, scope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                .flatMap(repo::delete);
    }
}
