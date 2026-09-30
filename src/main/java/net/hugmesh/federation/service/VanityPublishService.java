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
 * <h2>TWO identity axes — never compare one to the other</h2>
 * This service straddles two DIFFERENT identities and the whole vanity surface was
 * broken for every real user because they were compared to each other:
 *
 * <ul>
 *   <li><b>LABEL axis</b> — {@code username}: the vanity DNS label behind
 *       {@code <username>.hugmesh.net} and the {@code profile-<username>} slug.
 *       It is Casdoor's LOGIN NAME, carried on the token as
 *       {@code preferred_username}. It is what user-bff-api sends in the path
 *       segment ({@code ProfileController.usernameOf} ->
 *       {@code FederationApiClient.publishVanity}), and it is what
 *       {@code federation_modules.owner_user_id} holds for a profile fragment (the
 *       value the {@code scope=user} ban writer targets — see
 *       {@link VanityService}'s owner-ban section).</li>
 *   <li><b>SUBJECT axis</b> — {@code jwt.getSubject()}: on this platform the Casdoor
 *       <b>UUID</b> on a real Casdoor JWT, and the composite
 *       {@code provider:handle} account id on a bff_-session synthetic principal
 *       (stated outright in user-bff-api's {@code CasdoorUserClient}). It is what
 *       {@code BundleController} stamps on every {@code user_modules} row as
 *       {@code owner_user_id}.</li>
 * </ul>
 *
 * <p><b>The two are NEVER equal for a real account.</b> An earlier revision of this
 * class asserted the opposite ("the Casdoor subject IS the username on this
 * platform") and acted on it in both directions:
 * <ol>
 *   <li>{@link #ownerGuard} compared the caller's SUBJECT to the LABEL, so EVERY
 *       non-admin publish/unpublish was a 403 — which is what a user saw as a failed
 *       {@code PUT /bff/user/profile} whenever they enabled Public + vanity; and</li>
 *   <li>the {@code user_modules} lookup filtered {@code owner_user_id} by the LABEL
 *       when that column holds the SUBJECT, so relaxing (1) alone would only have
 *       converted the 403 into a 404.</li>
 * </ol>
 *
 * <h2>Owner-scoping (matches the {@code BundleController} owner-or-admin pattern)</h2>
 * The {@code username} path segment MUST equal the caller's own vanity LABEL
 * (case-insensitively — {@code ValidationPatterns.USERNAME} admits upper case while
 * the DNS label is lower-cased), UNLESS the caller holds {@code ROLE_ADMIN} or
 * {@code ROLE_SUPERADMIN}. A non-owner, non-admin caller is rejected with 403 BEFORE
 * any read or write runs. A caller whose token carries NO label claim fails CLOSED
 * (403): the label is never derived from the subject, because a subject-shaped value
 * that happened to equal a victim's label would otherwise buy ownership of it.
 * The bundle read is scoped on the SUBJECT axis (see
 * {@link #activeBundleForCaller}).
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
     * @param callerSubject the authenticated JWT SUBJECT (Casdoor UUID / bff_ composite).
     *                    Used ONLY as the {@code user_modules.owner_user_id} filter —
     *                    never compared to {@code username}. See the class javadoc.
     * @param callerLabel the caller's own vanity LABEL from the token's
     *                    {@code preferred_username}/{@code name} claim, or {@code null}
     *                    when the token carries neither (fails closed). This is the
     *                    value compared to {@code username}.
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
    public Mono<FederationModule> publish(String callerSubject, String callerLabel, boolean admin,
                                          String username, String displayName,
                                          PrincipalDomain scope) {
        ResponseStatusException owner = ownerGuard(callerSubject, callerLabel, admin, username);
        if (owner != null) {
            return Mono.error(owner);
        }
        ResponseStatusException reserved = reservedGuard(username);
        if (reserved != null) {
            return Mono.error(reserved);
        }
        String slug = VanityService.profileSlug(username);
        // SUBJECT axis: user_modules.owner_user_id is what BundleController.put stamps
        // (jwt.getSubject()), NOT the DNS label. Filtering it by `username` here is what
        // made the guard fix alone insufficient — see the class javadoc.
        return activeBundleForCaller(slug, callerSubject, admin, scope)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND,
                        "no uploaded bundle for " + slug + " — PUT /api/federation/bundles/" + slug
                                + " before publishing a vanity profile")))
                .flatMap(bundle -> upsertFragment(bundle, slug, username, displayName, scope))
                // Best-effort skeleton mint — mirrors ModuleRegistryService.create's
                // profile-fragment side-effect. A skeleton-write failure never fails
                // the publish; the slug UNIQUE column is the authoritative backstop.
                .flatMap(saved -> usernames.grant(username, username)
                        .onErrorResume(e -> Mono.empty())
                        .thenReturn(saved));
    }

    /**
     * The {@link #publish} leg once the caller's bundle is found: load (or start) the
     * {@code profile-<username>} row, refuse an admin-suppressed one with 409, else apply
     * the publish and save.
     *
     * @param bundle      the caller's active {@code user_modules} bundle for the slug
     * @param slug        the {@code profile-<username>} fragment slug
     * @param username    the vanity username / path segment being published
     * @param displayName optional display name to stamp on the fragment row
     * @param scope       the caller's resolved tenant scope (stamps {@code domain} on INSERT only)
     * @return a {@code Mono} emitting the saved {@link FederationModule}
     */
    private Mono<FederationModule> upsertFragment(UserModule bundle, String slug, String username,
                                                  String displayName, PrincipalDomain scope) {
        return modules.findBySlug(slug)
                .defaultIfEmpty(newModule(slug, username, scope))
                .flatMap(module -> {
                    if (adminSuppressed(module)) {
                        return Mono.<FederationModule>error(new ResponseStatusException(CONFLICT,
                                "profile '" + username + "' was administratively unpublished "
                                        + "and can only be restored by an admin via POST "
                                        + "/api/federation/overrides/" + slug + "/rearm"));
                    }
                    applyPublish(module, bundle, displayName, username);
                    return modules.save(module);
                });
    }

    /**
     * Unpublish (suppress) the caller's {@code profile-<username>} fragment:
     * flips {@code visibility='internal'} and {@code enabled=false} — the
     * symmetric counterpart to {@link #publish}. Never deletes the row (history +
     * the confusable-skeleton grant stay intact for a future republish).
     * Idempotent: completes successfully whether or not a fragment row exists yet
     * (unpublishing a never-published profile is a no-op, not an error).
     *
     * @param callerSubject the authenticated JWT SUBJECT — presence-checked only (401);
     *                 never compared to {@code username}. See the class javadoc.
     * @param callerLabel the caller's own vanity LABEL from the token, or {@code null}
     *                 when absent (fails closed with 403)
     * @param admin    {@code true} when the caller holds ROLE_ADMIN/ROLE_SUPERADMIN
     * @param username the vanity username / path segment being unpublished
     * @return a {@code Mono<Void>} completing once the row (if any) is suppressed
     * @throws ResponseStatusException 401 missing subject, 403 not owner/admin
     */
    public Mono<Void> unpublish(String callerSubject, String callerLabel, boolean admin,
                                String username) {
        ResponseStatusException violation = ownerGuard(callerSubject, callerLabel, admin, username);
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

    /**
     * Owner-or-admin gate, on the LABEL axis.
     *
     * <p>{@code callerSubject} is only presence-checked (an absent subject is an
     * unauthenticated call, 401). Ownership is decided by comparing the caller's own
     * vanity LABEL to the {@code username} path segment — the axis user-bff-api
     * actually addresses this endpoint by. Comparing the SUBJECT to it (the pre-fix
     * behaviour) 403'd every real account, because the subject is a Casdoor UUID.
     *
     * <p>Fails CLOSED on a missing label: {@code callerLabel == null} is a 403, never
     * a fallback to the subject. A subject-derived fallback would let any principal
     * whose subject string happened to equal a victim's DNS label publish or take
     * down that victim's profile.
     *
     * <p>The comparison is case-insensitive and trims: {@code ValidationPatterns.USERNAME}
     * admits upper case and Casdoor does not lower-case a login name, while the vanity
     * DNS label is lower-cased — a case-sensitive equality would 403 every user whose
     * login name has a capital letter.
     */
    private static ResponseStatusException ownerGuard(String callerSubject, String callerLabel,
                                                      boolean admin, String username) {
        if (callerSubject == null || callerSubject.isBlank()) {
            return new ResponseStatusException(UNAUTHORIZED, "missing authenticated subject");
        }
        if (admin) {
            return null;
        }
        if (!labelsMatch(callerLabel, username)) {
            return new ResponseStatusException(FORBIDDEN,
                    "cannot publish or unpublish another user's vanity profile");
        }
        return null;
    }

    /** Case-insensitive, trimmed equality of two vanity DNS labels; a null/blank on
     *  either side never matches (fail closed). */
    private static boolean labelsMatch(String a, String b) {
        if (a == null || a.isBlank() || b == null || b.isBlank()) {
            return false;
        }
        return a.trim().equalsIgnoreCase(b.trim());
    }

    /**
     * The active {@code user_modules} row the caller may publish FROM — the SUBJECT-axis
     * three-tier cut, mirroring {@code BundleService.activeRowForCaller} (this service
     * holds the repository directly; that method is private to its own service).
     *
     * <ul>
     *   <li>SUPERADMIN — un-pinned: the slug's active row in ANY brand.</li>
     *   <li>per-domain ADMIN — the slug's active row pinned to the caller's brand, so a
     *       same-slug row in another brand resolves EMPTY (404), never a cross-tenant
     *       publish. An admin publishing on another user's behalf cannot use their own
     *       subject as the owner filter (the bundle is the target user's), so the owner
     *       predicate is dropped here rather than mis-applied.</li>
     *   <li>per-domain non-admin — ONLY their own active row, owner = JWT SUBJECT.</li>
     * </ul>
     */
    private Mono<UserModule> activeBundleForCaller(String slug, String callerSubject, boolean admin,
                                                   PrincipalDomain scope) {
        if (scope != null && scope.superadmin()) {
            return bundles.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(slug);
        }
        if (admin) {
            return bundles.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(
                    slug, domainOf(scope));
        }
        return bundles.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(
                slug, callerSubject);
    }

    /** The caller's brand for a READ predicate ({@code "default"} when scope-less) —
     *  mirrors {@code BundleService.domainOf}. Distinct from {@link #domainForWrite},
     *  which additionally collapses a SUPERADMIN to {@code "default"} when STAMPING. */
    private static String domainOf(PrincipalDomain scope) {
        return scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();
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

    /**
     * Stamp the fragment row from the caller's bundle.
     *
     * <p>{@code owner_user_id} is stamped with the vanity LABEL, NOT
     * {@code bundle.getOwnerUserId()} (which is the SUBJECT — see the class javadoc).
     * That column is the axis {@link VanityService}'s owner-ban gate resolves an
     * active {@code scope=user} override by, and the ban writer targets the username;
     * stamping a Casdoor UUID there would leave every vanity-profile ban inert while
     * the fragment kept resolving at the vanity host. The cosmetic {@code displayName}
     * falls back to the label for the same reason — a raw UUID is not a display name.
     */
    private static void applyPublish(FederationModule module, UserModule bundle,
                                     String displayName, String username) {
        Instant now = Instant.now();
        if (module.getCreatedAt() == null) {
            module.setCreatedAt(now);
        }
        module.setKind(FRAGMENT_KIND);
        module.setOwnerUserId(username);
        String name = (displayName != null && !displayName.isBlank())
                ? displayName
                : (module.getDisplayName() != null && !module.getDisplayName().isBlank()
                        ? module.getDisplayName() : username);
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
