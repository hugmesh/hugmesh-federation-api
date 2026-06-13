package systems.snapdragon.federation.controller;

import java.util.Set;

/**
 * THE CANONICAL RESERVED USERNAME / DNS-LABEL LIST (case-insensitive).
 *
 * <p>A vanity username (the FIRST DNS label of {@code <user>.snapdragon.systems}
 * or {@code <user>.snapdragon.games}) must NOT equal any of these, because each
 * one is — or could collide with — a dedicated app path-prefix route or a platform
 * service subdomain. A prefix-collision (username exactly equals a reserved label)
 * is a hard 404 in the serving layer AND rejected at the DB layer.
 *
 * <h2>CANONICAL SOURCE — the gateway routes (auditable)</h2>
 * This set is the UNION of the deployed route prefixes / reserved subdomains:
 * <ul>
 *   <li><b>fe-gateway</b> route prefixes (snapdragon-fe-gateway/application-fe.yml +
 *       the snapdragon.systems host nginx /_remotes): {@code admin, apidocs, be, bff,
 *       _fragments, login, mod, user};</li>
 *   <li><b>be-gateway</b> route prefixes (snapdragon-be-gateway/application-be.yml):
 *       {@code api, _matrix, oauth};</li>
 *   <li><b>reserved subdomains</b> (snapdragon.systems): {@code id, api, matrix,
 *       mastodon, pleroma, forum, wiki, scale, headscale, www} — {@code forum} is
 *       the phpBB forum surface (served at the apex path {@code /social/forum}) and
 *       {@code wiki} is the default-on Kiwix wiki surface (served at the apex path
 *       {@code /wiki}); both labels are reserved defensively so a vanity
 *       {@code forum.<domain>} / {@code wiki.<domain>} can never collide);</li>
 *   <li><b>snapdragon.GAMES app route prefixes</b> — DERIVED from
 *       snapdragon.games/frontend/nginx.conf {@code /_remotes/<slug>/} blocks +
 *       location prefixes + the {@code <service>.snapdragon.games} subdomains
 *       (compose.prod.yml): the remote slugs {@code admin, api-docs, banned,
 *       games-dodecahedron, games-rpg-maker, games-three-wizards, games-vn-maker,
 *       login, mod, producer-registration, publisher, registration, wasm-fragment},
 *       the path prefixes {@code api, docs, _remotes}, and the games-flavoured
 *       front-door labels {@code games, play, wasm, producer};</li>
 *   <li><b>defensive web reserved names</b> (never a username, regardless of route):
 *       {@code root, static, assets, public, health, healthz, actuator, metrics,
 *       well-known, favicon, robots, sitemap, status, support, help, social, auth,
 *       logout, oauth2, fragments, users, gm, pki, vault, argocd, gitlab,
 *       registry}.</li>
 * </ul>
 *
 * <p><b>SHARED SOURCE.</b> This exact list text is mirrored verbatim in
 * snapdragon-user-bff-api ({@code systems.snapdragon.userbff.profile.ReservedNames})
 * so the SERVING layer (this repo) and the USER profile validation/DB layer agree
 * on a single vocabulary. Keep the two copies identical; the canonical source of
 * truth is the gateway route config referenced above. The DB-level forbidden slugs
 * ({@code profile-<reserved>}) are generated from this same set (changeset 016).
 */
public final class ReservedNames {

    private ReservedNames() {}

    /**
     * Reserved first DNS labels / usernames. Lower-case; callers MUST lower-case the
     * candidate before {@link Set#contains}. Defence-in-depth: the gateway route
     * order already prevents service subdomains from reaching the vanity wildcard,
     * but a direct call with a reserved Host can never resolve a "user" named e.g.
     * {@code api} or {@code admin}.
     */
    public static final Set<String> RESERVED_LABELS = Set.of(
            // --- fe-gateway route prefixes (snapdragon.systems front door) ---
            "admin", "apidocs", "be", "bff", "_fragments", "login", "mod", "user",
            // --- be-gateway route prefixes ---
            "api", "_matrix", "oauth",
            // --- reserved subdomains (snapdragon.systems) ---
            "id", "matrix", "mastodon", "pleroma", "forum", "wiki", "scale", "headscale", "www",
            // --- snapdragon.GAMES app route prefixes (derived: nginx /_remotes/<slug>/
            //     + location prefixes + <service>.snapdragon.games subdomains) ---
            "games", "play", "wasm", "producer", "publisher", "banned",
            "api-docs", "docs", "_remotes", "producer-registration", "registration",
            "wasm-fragment", "games-dodecahedron", "games-rpg-maker",
            "games-three-wizards", "games-vn-maker",
            // --- defensive web reserved names ---
            "root", "static", "assets", "public", "health", "healthz", "actuator",
            "metrics", "well-known", "favicon", "robots", "sitemap", "status",
            "support", "help", "social", "auth", "logout", "oauth2", "fragments",
            "users", "gm", "pki", "vault", "argocd", "gitlab", "registry");

    /** Whether a candidate first-label / username is reserved (case-insensitive). */
    public static boolean isReserved(String label) {
        return label != null && RESERVED_LABELS.contains(label.trim().toLowerCase());
    }
}
