package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.VanityProfileDto;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;

/**
 * Resolves a vanity subdomain ({@code <username>.snapdragon.systems}) to the
 * user's PUBLIC profile-fragment descriptor — the read path behind
 * {@code GET /api/federation/vanity/{username}}.
 *
 * <h2>username &lt;-&gt; fragment association (the chosen convention)</h2>
 * A user's public profile is ONE {@code federation_modules} row with:
 * <ul>
 *   <li>{@code slug = "profile-" + username}  — deterministic from the username,
 *       so the resolve is a single unique-slug lookup with NO extra mapping
 *       table (the slug column is already UNIQUE + indexed);</li>
 *   <li>{@code kind = "fragment"}             — served by the remote-fragment
 *       sync-and-serve-static fleet (same path as every other fragment bundle);</li>
 *   <li>{@code owner_user_id = username}      — the Casdoor subject, so the
 *       admin/mod scope=user kill-switch already covers a user's vanity profile
 *       with no new wiring;</li>
 *   <li>{@code visibility = "public"}         — the GATE. Only public fragments
 *       are ever resolvable here.</li>
 * </ul>
 *
 * <p>The slug convention is the source of truth for the resolve. {@code owner_user_id}
 * is set for the kill-switch / ownership, but the resolve keys on the slug so the
 * lookup stays a single indexed equality (no scan).
 *
 * <h2>Why this is safe to expose without a JWT</h2>
 * The finder ({@link FederationModuleRepository#findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState})
 * filters {@code visibility='public'} + {@code enabled} + {@code circuit_state='closed'}
 * IN THE QUERY, so an internal, disabled, or kill-switched fragment can never be
 * returned. A non-existent / non-public username yields an empty Mono -> the
 * controller maps it to 404. Fully reactive (Mono throughout — no blocking).
 *
 * <h2>Owner-ban check (account-states foundation)</h2>
 * After the public-fragment finder returns, the resolve ALSO consults the
 * kill-switch store for an ACTIVE scope=user override targeting the fragment's
 * {@code owner_user_id} ({@link FederationOverrideRepository#findByScopeAndTargetAndClearedAtIsNull}).
 * If one exists the resolve returns {@code Mono.empty()} (-> 404) EVEN for a
 * public + enabled + circuit-closed fragment: an access-suspended user's vanity
 * profile must disappear, and a suspension writes its row directly via
 * {@link OverrideService#applyUserScope} (no module mutation), so the finder alone
 * would still serve the profile. Identity is pinned to {@code owner_user_id} — the
 * value the ban writer targets and the publisher stores — NOT the Casdoor sub.
 */
@Service
public class VanityService {

    /** kind of a profile fragment (matches the seed + the remote-fragment fleet's filter). */
    static final String FRAGMENT_KIND = "fragment";
    /** Only public fragments are ever resolvable at a vanity host. */
    static final String PUBLIC_VISIBILITY = "public";
    /** Kill-switch: only circuit-closed rows ship (mirrors the manifest read path). */
    static final String CIRCUIT_CLOSED = "closed";
    /** Scope of an owner-level (per-user) kill-switch / access-suspension override. */
    static final String USER_SCOPE = "user";

    private final FederationModuleRepository repo;
    private final FederationOverrideRepository overrides;

    public VanityService(FederationModuleRepository repo, FederationOverrideRepository overrides) {
        this.repo = repo;
        this.overrides = overrides;
    }

    /** The deterministic slug for a username's profile fragment. */
    public static String profileSlug(String username) {
        return "profile-" + username;
    }

    /**
     * Resolve a username to its PUBLIC profile-fragment descriptor, or an empty
     * Mono if no serveable public profile fragment exists for it (the controller
     * turns empty into 404). Never emits an internal / disabled / circuit-broken
     * fragment — the finder's predicate guarantees it — AND never emits a fragment
     * whose owner is under an ACTIVE scope=user override (access-suspension /
     * owner-level kill), even when the fragment is public + enabled + circuit-closed.
     */
    public Mono<VanityProfileDto> resolve(String username) {
        if (username == null || username.isBlank()) {
            return Mono.empty();
        }
        String trimmed = username.trim();
        String slug = profileSlug(trimmed);
        return repo
                .findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                        slug, FRAGMENT_KIND, PUBLIC_VISIBILITY, CIRCUIT_CLOSED)
                // Belt-and-braces: re-assert the public-fragment invariant in code
                // so the public projection can NEVER be built from a non-public row
                // even if the finder were ever changed.
                .filter(VanityService::isPublicProfileFragment)
                // Owner-ban gate: a fragment whose owner_user_id is under an ACTIVE
                // scope=user override (e.g. access_suspension) is suppressed even
                // though it is public+enabled+closed. filterWhen keeps it reactive
                // (one indexed override lookup, only when a public fragment matched).
                .filterWhen(this::ownerNotBanned)
                .map(m -> VanityProfileDto.from(trimmed, m));
    }

    /**
     * True iff the fragment's owner is NOT under an active scope=user override.
     * Pins identity on {@code owner_user_id} — the field the ban writer
     * ({@link OverrideService#applyUserScope}) targets and the publisher stores —
     * NOT the Casdoor sub. A NULL owner (first-party / system fragment) can never
     * match a per-user ban, so it is allowed. {@code hasElements()} on the
     * active-override finder yields the ban verdict in one indexed query.
     */
    private Mono<Boolean> ownerNotBanned(FederationModule m) {
        String owner = m.getOwnerUserId();
        if (owner == null || owner.isBlank()) {
            return Mono.just(true);
        }
        return overrides
                .findByScopeAndTargetAndClearedAtIsNull(USER_SCOPE, owner)
                .hasElements()
                .map(banned -> !banned);
    }

    /** In-code guard mirroring the finder predicate (visibility=public + kind=fragment). */
    static boolean isPublicProfileFragment(FederationModule m) {
        return m != null
                && FRAGMENT_KIND.equalsIgnoreCase(m.getKind())
                && PUBLIC_VISIBILITY.equalsIgnoreCase(m.getVisibility());
    }
}
