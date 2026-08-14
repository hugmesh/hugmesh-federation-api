package net.hugmesh.federation.controller;

import java.util.Set;

/**
 * THE CANONICAL RESERVED USERNAME / DNS-LABEL LIST (case-insensitive).
 *
 * <p>A vanity username (the FIRST DNS label of {@code <user>.hugmesh.net}
 * or {@code <user>.hugmesh.games}) must NOT equal any of these, because each
 * one is — or could collide with — a dedicated app path-prefix route or a platform
 * service subdomain. A prefix-collision (username exactly equals a reserved label)
 * is a hard 404 in the serving layer AND rejected at the DB layer.
 *
 * <h2>CANONICAL SOURCE — the gateway routes (auditable)</h2>
 * This set is the UNION of the deployed route prefixes / reserved subdomains:
 * <ul>
 *   <li><b>fe-gateway</b> route prefixes (hugmesh-fe-gateway/application-fe.yml +
 *       the hugmesh.net host nginx /_remotes): {@code admin, apidocs, be, bff,
 *       _fragments, login, mod, user};</li>
 *   <li><b>be-gateway</b> route prefixes (hugmesh-be-gateway/application-be.yml):
 *       {@code api, _matrix, oauth};</li>
 *   <li><b>reserved subdomains</b> (hugmesh.net): {@code id, api, matrix,
 *       mastodon, pleroma, forum, wiki, scale, headscale, www} — {@code forum} is
 *       the phpBB forum surface (served at the apex path {@code /social/forum}) and
 *       {@code wiki} is the default-on Kiwix wiki surface (served at the apex path
 *       {@code /wiki}); both labels are reserved defensively so a vanity
 *       {@code forum.<domain>} / {@code wiki.<domain>} can never collide);</li>
 *   <li><b>hugmesh.GAMES app route prefixes</b> — DERIVED from
 *       hugmesh.games/frontend/nginx.conf {@code /_remotes/<slug>/} blocks +
 *       location prefixes + the {@code <service>.hugmesh.games} subdomains
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
 * hugmesh-user-bff-api ({@code net.hugmesh.userbff.profile.ReservedNames})
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
            // --- fe-gateway route prefixes (hugmesh.net front door) ---
            "admin", "apidocs", "be", "bff", "_fragments", "login", "mod", "user",
            // superadmin: the TAILNET superadmin Service Catalog console is served at
            // /superadmin/service-catalog/** on the superadmin-gateway — a dedicated
            // first-segment route prefix (canonical reserved-prefixes.yaml).
            "superadmin",
            // hmdm / attest: the Headwind MDM (/hmdm/manage/**, /hmdm/rest/**) and
            // AttestationServer (/attest/auditor/**, /attest/api/**) tailnet-only
            // superadmin-gateway route prefixes (canonical reserved-prefixes.yaml
            // rev 7/8 — drift fix: the canonical YAML instructed the app-repo
            // copies to add these when the routes shipped).
            "hmdm", "attest",
            // character-studio: the Character Studio (VN) micro-frontend remote is
            // served at /character-studio/** on the fe-gateway — a dedicated
            // first-segment route prefix (canonical reserved-prefixes.yaml rev 4).
            "character-studio",
            // character-forge: the Character Forge (3D) micro-frontend remote is
            // served at /character-forge/** on the fe-gateway (BFF at
            // /bff/character-forge/**) — a dedicated first-segment route prefix
            // (canonical reserved-prefixes.yaml rev 9).
            "character-forge",
            // --- be-gateway route prefixes / publicly-routable homeserver surfaces ---
            // _synapse + media: PUBLICLY-ROUTABLE homeserver client surfaces the
            // route-access seed deploys — /_synapse/** (Matrix Synapse-compat,
            // matrix-host-scoped) and /media/** (Mastodon media). Real first-segment
            // route prefixes, so a vanity username equal to either would shadow them.
            "api", "_matrix", "_synapse", "media", "oauth",
            // v1: the edge-AI analysis API is served at /v1/analyze/** on the
            // be-gateway — a dedicated first-segment route prefix (canonical
            // reserved-prefixes.yaml rev 4).
            "v1",
            // --- reserved subdomains (hugmesh.net) ---
            // forum/phpbb: the phpBB community forum surfaces; owncast/wiki/tube:
            // optional video/wiki/streaming services — all reserved so a vanity
            // subdomain can never collide (canonical reserved-prefixes.yaml).
            "id", "matrix", "mastodon", "pleroma", "forum", "phpbb", "wiki",
            "owncast", "tube", "scale", "headscale", "www",
            // ai: the edge-AI inference tier is served on its own host
            // ai.hugmesh.net (the raw model API plus the more specific
            // /v1/analyze/** analysis API) — a dedicated reserved host (canonical
            // reserved-prefixes.yaml rev 6).
            "ai",
            // --- hugmesh.GAMES app route prefixes (derived: nginx /_remotes/<slug>/
            //     + location prefixes + <service>.hugmesh.games subdomains) ---
            "games", "play", "wasm", "producer", "publisher", "banned",
            "api-docs", "docs", "_remotes", "producer-registration", "registration",
            "wasm-fragment", "games-dodecahedron", "games-rpg-maker",
            "games-three-wizards", "games-vn-maker", "games-instances-console",
            // games-character-forge / games-shadows-of-the-net: the 3D character
            // maker + the XR chat room published into hugmesh.games as wasm
            // games (nginx /_remotes/<slug>/ blocks, existing games-* pattern).
            "games-character-forge", "games-shadows-of-the-net",
            // --- defensive web reserved names ---
            "root", "static", "assets", "public", "health", "healthz", "actuator",
            "metrics", "well-known", "favicon", "robots", "sitemap", "status",
            "support", "help", "social", "auth", "logout", "oauth2", "fragments",
            "users", "gm", "pki", "vault", "argocd", "gitlab", "registry",
            // index.html, favicon.ico, importmap.json, remoteEntry.json: the exact
            // webroot filenames the fe-gateway anonymous-SPA-shell route-access rows
            // reference as literal first-segment url_patterns — distinct literal
            // segments from the already-reserved bare favicon label above (canonical
            // reserved-prefixes.yaml rev 5).
            "index.html", "favicon.ico", "importmap.json", "remoteEntry.json");

    /** Whether a candidate first-label / username is reserved (case-insensitive). */
    public static boolean isReserved(String label) {
        return label != null && RESERVED_LABELS.contains(label.trim().toLowerCase());
    }
}
