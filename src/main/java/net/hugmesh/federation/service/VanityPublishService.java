package net.hugmesh.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.controller.ReservedNames;
import net.hugmesh.federation.model.FederationModule;
import net.hugmesh.federation.model.UserModule;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.federation.repository.UserModuleRepository;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * The OWNER-SCOPED self-publish/unpublish write path for a vanity profile —
 * the "missing link" the README's <em>Vanity PUBLISH path (cross-service)</em>
 * section calls out: {@code hugmesh-user-bff-api}'s {@code ProfileService.save}
 * persists {@code visibility}/{@code vanitySubdomainEnabled} but (before this
 * service existed) made no federation call, so flipping those flags never
 * registered/published a {@code federation_modules} fragment row.
 *
 * <h2>What this upserts</h2>
 * A user's public profile is ONE {@code federation_modules} row keyed on the
 * deterministic slug {@code profile-<username>} (see {@link VanityService}). This
 * service builds/refreshes that row FROM the caller's own ALREADY-UPLOADED
 * {@code user_modules} bundle for the same slug (see {@code BundleController.put}
 * / {@code PUT /api/federation/bundles/profile-<username>}) — it never accepts
 * {@code remoteEntryUrl} / {@code contentHash} from the request body, so a caller
 * cannot register a fragment pointing at bytes they never uploaded.
 *
 * <h2>Owner-scoping (matches the {@code BundleController} owner-or-admin pattern)</h2>
 * The {@code username} path segment MUST equal the caller's own JWT subject
 * (the Casdoor subject IS the username on this platform — see
 * {@code ProfileService.usernameOf} in user-bff-api), UNLESS the caller holds
 * {@code ROLE_ADMIN} or {@code ROLE_SUPERADMIN}. A non-owner, non-admin caller
 * is rejected with 403 BEFORE any read or write runs.
 *
 * <h2>Reserved-name defence (write-layer, mirrors {@code ProfileService.save})</h2>
 * Publishing is rejected with 400 when the username is an EXACT reserved label
 * ({@link ReservedNames}) or a CONFUSABLE of one ({@link UsernameSkeletonService})
 * — belt-and-braces alongside the identical guard already enforced in
 * user-bff-api's {@code ProfileService.save} and the {@code VanityController}
 * READ-layer defence.
 *
 * <h2>Honest failure</h2>
 * Every rejection (no uploaded bundle yet, ownership mismatch, reserved name) is
 * an error signal — never a silently-degraded 200 — so a caller (the user-bff
 * proxy) can propagate a truthful failure instead of reporting "published" when
 * it was not.
 *
 * <h2>Admin per-module kill-switch is never silently bypassed by self-publish</h2>
 * {@code OverrideController}'s {@code action=unpublish} kill-switch
 * ({@code POST /api/federation/overrides}, scope {@code user}/{@code role} with NO
 * explicit {@code scopeValue}) suppresses a SINGLE module by setting
 * {@code enabled=false} directly on the {@code federation_modules} row — it does
 * NOT touch {@code visibility} (unlike this service's own {@link #unpublish}, which
 * always flips {@code visibility=internal} alongside {@code enabled=false}). That
 * asymmetry is the load-bearing signal this service checks before every republish:
 * an EXISTING row that is still {@code visibility=public} but {@code enabled=false}
 * was disabled by something other than a self-unpublish (i.e. the admin
 * kill-switch), and — per {@code OverrideController}'s own docs — the ONLY intended
 * recovery from that state is the ADMIN-only {@code POST
 * /api/federation/overrides/{moduleSlug}/rearm} endpoint. {@link #publish} detects
 * this state via {@link #adminSuppressed(FederationModule)} and fails closed with
 * {@code 409 CONFLICT} rather than flipping {@code enabled} back to {@code true} —
 * a self-service (or unrelated profile-edit-triggered) republish must never
 * silently undo a targeted admin moderation action. (A full account-level ban —
 * {@code applyUserScope}, an unpublish with an explicit {@code scopeValue} equal to
 * the owner's username — is a separate, ALREADY-covered mechanism: it writes no
 * module-row mutation at all, so it is enforced purely by
 * {@code VanityService}'s read-time owner-ban check and is unaffected by this
 * service either way.)
 *
 * @see net.hugmesh.federation.controller.VanityController
 * @see VanityService
 * @see UsernameAvailabilityService#grant(String, String)
 */
@Service
public class VanityPublishService {

    /** kind of a profile fragment (matches {@link VanityService#FRAGMENT_KIND}). */
    static final String FRAGMENT_KIND = "fragment";
    static final String PUBLIC_VISIBILITY = "public";
    static final String INTERNAL_VISIBILITY = "internal";
    /** Version stamped on every self-published profile fragment. The real version
     *  key for a fragment's bytes is {@code contentHash} (content-addressed); this
     *  field only satisfies the NOT-NULL/required {@code version} column. */
    static final String PROFILE_MODULE_VERSION = "1.0.0";
    static final String DEFAULT_ENTRY_FILE = "remoteEntry.json";

    private final FederationModuleRepository modules;
    private final UserModuleRepository bundles;
    private final UsernameAvailabilityService usernames;
    private final UsernameSkeletonService skeletons;

    public VanityPublishService(FederationModuleRepository modules, UserModuleRepository bundles,
                                UsernameAvailabilityService usernames, UsernameSkeletonService skeletons) {
        this.modules = modules;
        this.bundles = bundles;
        this.usernames = usernames;
        this.skeletons = skeletons;
    }

    /**
     * Publish (create or refresh) the caller's {@code profile-<username>} fragment
     * from their own currently-active bundle. Fails CLOSED — a federation-layer
     * error (no bundle, reserved name, not-owner) is always an error signal, never
     * a downgraded success.
     *
     * @param caller      the authenticated JWT subject
     * @param admin       {@code true} when the caller holds ROLE_ADMIN/ROLE_SUPERADMIN
     *                    (may publish on behalf of another username)
     * @param username    the vanity username / path segment being published
     * @param displayName optional display name to stamp on the fragment row; when
     *                    blank, the existing row's displayName (or the username
     *                    itself, on first publish) is kept
     * @param scope       the caller's resolved tenant scope; stamps {@code domain}
     *                    on a first-time (INSERT) publish only — an existing row's
     *                    domain is never changed by a republish
     * @return a {@code Mono} emitting the upserted, now-public {@link FederationModule}
     * @throws ResponseStatusException 401 missing subject, 403 not owner/admin,
     *                                 400 reserved/confusable username, 404 no
     *                                 uploaded bundle yet for the slug, 409 the
     *                                 existing row was suppressed by the admin
     *                                 kill-switch (see class javadoc) — republish
     *                                 must go through {@code POST
     *                                 /api/federation/overrides/{moduleSlug}/rearm}
     */
    public Mono<FederationModule> publish(String caller, boolean admin, String username,
                                          String displayName, PrincipalDomain scope) {
        ResponseStatusException owner = ownerGuard(caller, admin, username);
        if (owner != null) {
            return Mono.error(owner);
        }
        ResponseStatusException reserved = reservedGuard(username);
        if (reserved != null) {
            return Mono.error(reserved);
        }
        String slug = VanityService.profileSlug(username);
        return bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(slug, username)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND,
                        "no uploaded bundle for " + slug + " — PUT /api/federation/bundles/" + slug
                                + " before publishing a vanity profile")))
                .flatMap(bundle -> modules.findBySlug(slug)
                        .defaultIfEmpty(newModule(slug, username, scope))
                        .flatMap(module -> {
                            if (adminSuppressed(module)) {
                                return Mono.<FederationModule>error(new ResponseStatusException(CONFLICT,
                                        "profile '" + username + "' was administratively unpublished "
                                                + "and can only be restored by an admin via POST "
                                                + "/api/federation/overrides/" + slug + "/rearm"));
                            }
                            applyPublish(module, bundle, displayName);
                            return modules.save(module);
                        }))
                // Best-effort skeleton mint — mirrors ModuleRegistryService.create's
                // profile-fragment side-effect. A skeleton-write failure never fails
                // the publish; the slug UNIQUE column is the authoritative backstop.
                .flatMap(saved -> usernames.grant(username, username)
                        .onErrorResume(e -> Mono.empty())
                        .thenReturn(saved));
    }

    /**
     * Unpublish (suppress) the caller's {@code profile-<username>} fragment:
     * flips {@code visibility='internal'} and {@code enabled=false} — the
     * symmetric counterpart to {@link #publish}. Never deletes the row (history +
     * the confusable-skeleton grant stay intact for a future republish).
     * Idempotent: completes successfully whether or not a fragment row exists yet
     * (unpublishing a never-published profile is a no-op, not an error).
     *
     * @param caller   the authenticated JWT subject
     * @param admin    {@code true} when the caller holds ROLE_ADMIN/ROLE_SUPERADMIN
     * @param username the vanity username / path segment being unpublished
     * @return a {@code Mono<Void>} completing once the row (if any) is suppressed
     * @throws ResponseStatusException 401 missing subject, 403 not owner/admin
     */
    public Mono<Void> unpublish(String caller, boolean admin, String username) {
        ResponseStatusException violation = ownerGuard(caller, admin, username);
        if (violation != null) {
            return Mono.error(violation);
        }
        String slug = VanityService.profileSlug(username);
        return modules.findBySlug(slug)
                .flatMap(module -> {
                    module.setVisibility(INTERNAL_VISIBILITY);
                    module.setEnabled(false);
                    module.setUpdatedAt(Instant.now());
                    return modules.save(module);
                })
                .then();
    }

    // ----- Guards -----

    private ResponseStatusException reservedGuard(String username) {
        if (ReservedNames.isReserved(username)) {
            return new ResponseStatusException(BAD_REQUEST,
                    "username '" + username + "' is a reserved platform name and cannot be published "
                            + "as a vanity profile");
        }
        if (skeletons.isReservedSkeleton(username)) {
            return new ResponseStatusException(BAD_REQUEST,
                    "username '" + username + "' is confusable with a reserved platform name and "
                            + "cannot be published as a vanity profile");
        }
        return null;
    }

    private static ResponseStatusException ownerGuard(String caller, boolean admin, String username) {
        if (caller == null || caller.isBlank()) {
            return new ResponseStatusException(UNAUTHORIZED, "missing authenticated subject");
        }
        if (!admin && !caller.equals(username)) {
            return new ResponseStatusException(FORBIDDEN,
                    "cannot publish or unpublish another user's vanity profile");
        }
        return null;
    }

    /**
     * True iff an EXISTING module row was suppressed by the admin per-module
     * kill-switch ({@code OverrideController} {@code action=unpublish}) rather than
     * this service's own {@link #unpublish}. See class javadoc for the full
     * rationale — the short version: {@code OverrideController}'s unpublish only
     * ever sets {@code enabled=false} and leaves {@code visibility} untouched, while
     * THIS service's {@link #unpublish} always moves {@code visibility} to
     * {@code internal} in the same write. So a row that is still
     * {@code visibility=public} yet {@code enabled=false} can only have been put in
     * that state by the admin kill-switch (or, transiently, by a still-in-flight
     * first publish that never reached {@link #applyPublish} — which never persists
     * a row, so that case cannot appear here at all). A brand-new (never persisted)
     * row is never suppressed: {@link FederationModule#getCreatedAt()} is only
     * non-null once a prior {@link #applyPublish} write has actually landed.
     *
     * @param module the (possibly not-yet-persisted) module row about to be
     *               republished
     * @return {@code true} iff republishing this row must be refused (409)
     */
    private static boolean adminSuppressed(FederationModule module) {
        return module.getCreatedAt() != null
                && !module.isEnabled()
                && PUBLIC_VISIBILITY.equalsIgnoreCase(module.getVisibility());
    }

    // ----- Upsert helpers -----

    private FederationModule newModule(String slug, String username, PrincipalDomain scope) {
        FederationModule m = new FederationModule();
        m.setSlug(slug);
        m.setKind(FRAGMENT_KIND);
        m.setOwnerUserId(username);
        m.setVersion(PROFILE_MODULE_VERSION);
        m.setCircuitState("closed");
        m.setDomain(domainForWrite(scope));
        return m;
    }

    private static void applyPublish(FederationModule module, UserModule bundle, String displayName) {
        Instant now = Instant.now();
        if (module.getCreatedAt() == null) {
            module.setCreatedAt(now);
        }
        module.setKind(FRAGMENT_KIND);
        module.setOwnerUserId(bundle.getOwnerUserId());
        String name = (displayName != null && !displayName.isBlank())
                ? displayName
                : (module.getDisplayName() != null && !module.getDisplayName().isBlank()
                        ? module.getDisplayName() : bundle.getOwnerUserId());
        module.setDisplayName(name);
        String entry = (bundle.getEntryFile() != null && !bundle.getEntryFile().isBlank())
                ? bundle.getEntryFile() : DEFAULT_ENTRY_FILE;
        module.setRemoteEntryUrl("/_fragments/" + module.getSlug() + "/" + entry);
        module.setContentHash(bundle.getContentHash());
        module.setVisibility(PUBLIC_VISIBILITY);
        module.setEnabled(true);
        if (module.getCircuitState() == null) {
            module.setCircuitState("closed");
        }
        if (module.getVersion() == null) {
            module.setVersion(PROFILE_MODULE_VERSION);
        }
        module.setMetadata(bundle.getManifestJson());
        module.setUpdatedAt(now);
    }

    private static String domainForWrite(PrincipalDomain scope) {
        return (scope != null && !scope.superadmin()) ? scope.domain() : "default";
    }
}
