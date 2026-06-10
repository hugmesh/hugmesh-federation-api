package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.VanityProfileDto;
import systems.snapdragon.federation.repository.FederationModuleRepository;

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
 */
@Service
public class VanityService {

    /** kind of a profile fragment (matches the seed + the remote-fragment fleet's filter). */
    static final String FRAGMENT_KIND = "fragment";
    /** Only public fragments are ever resolvable at a vanity host. */
    static final String PUBLIC_VISIBILITY = "public";
    /** Kill-switch: only circuit-closed rows ship (mirrors the manifest read path). */
    static final String CIRCUIT_CLOSED = "closed";

    private final FederationModuleRepository repo;

    public VanityService(FederationModuleRepository repo) {
        this.repo = repo;
    }

    /** The deterministic slug for a username's profile fragment. */
    public static String profileSlug(String username) {
        return "profile-" + username;
    }

    /**
     * Resolve a username to its PUBLIC profile-fragment descriptor, or an empty
     * Mono if no serveable public profile fragment exists for it (the controller
     * turns empty into 404). Never emits an internal / disabled / circuit-broken
     * fragment — the finder's predicate guarantees it.
     */
    public Mono<VanityProfileDto> resolve(String username) {
        if (username == null || username.isBlank()) {
            return Mono.empty();
        }
        String slug = profileSlug(username.trim());
        return repo
                .findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState(
                        slug, FRAGMENT_KIND, PUBLIC_VISIBILITY, CIRCUIT_CLOSED)
                // Belt-and-braces: re-assert the public-fragment invariant in code
                // so the public projection can NEVER be built from a non-public row
                // even if the finder were ever changed.
                .filter(VanityService::isPublicProfileFragment)
                .map(m -> VanityProfileDto.from(username.trim(), m));
    }

    /** In-code guard mirroring the finder predicate (visibility=public + kind=fragment). */
    static boolean isPublicProfileFragment(FederationModule m) {
        return m != null
                && FRAGMENT_KIND.equalsIgnoreCase(m.getKind())
                && PUBLIC_VISIBILITY.equalsIgnoreCase(m.getVisibility());
    }
}
