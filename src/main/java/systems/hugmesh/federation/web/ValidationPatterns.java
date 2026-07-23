package systems.hugmesh.federation.web;

/**
 * Shared regex / size constants for jakarta Bean Validation across the federation
 * controllers + request DTOs. Centralised so the API-level validation stays in
 * lock-step with the DB column types / CHECK vocabularies (the security-hardening
 * API&lt;-&gt;DB parity audit):
 *
 * <ul>
 *   <li>{@link #SLUG} — a safe module/profile slug: a DNS-label-ish token
 *       ({@code [a-z0-9] [a-z0-9-]* [a-z0-9]}, 1-128 chars). Matches what the
 *       {@code slug} column (UNIQUE, indexed) can safely hold and what the vanity
 *       resolve expects; rejects path-traversal / whitespace / uppercase before any
 *       DB call.</li>
 *   <li>{@link #CONTENT_HASH} — 64 lower-hex chars (a SHA-256 the bundle pipeline
 *       produces; the {@code content_hash varchar(64)} column).</li>
 *   <li>The enum patterns mirror the 018 CHECK constraints EXACTLY so a bad value
 *       is a 400 (field error) before it ever reaches the DB CHECK.</li>
 * </ul>
 */
public final class ValidationPatterns {

    private ValidationPatterns() {}

    /** DNS-label-style slug: lower-alnum + internal hyphens, 1-128 chars. */
    public static final String SLUG = "^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$";
    public static final int SLUG_MAX = 128;

    /**
     * A vanity-username PATH token: case-insensitive alnum + hyphen, with an
     * OPTIONAL leading underscore so the reserved service labels ({@code _matrix},
     * {@code _fragments}, {@code _remotes}) still PASS the format check and reach
     * the in-controller reserved-name 404 (the reserved-name rule must NOT be
     * weakened — a reserved label is a deliberate 404, never a 400). This blocks
     * path-traversal / dots / slashes / whitespace before the resolve runs; the
     * reserved-label set + the public-fragment query do the rest.
     */
    public static final String USERNAME = "^_?[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})?$";

    /** SHA-256 hex content hash (the content-addressed version key). */
    public static final String CONTENT_HASH = "^[a-f0-9]{64}$";

    // ---- enum patterns — mirror the 018 DB CHECK vocabularies exactly ----

    /** federation_modules.kind */
    public static final String MODULE_KIND = "^(host|remote-shell|remote-game|fragment)$";
    /** federation_modules.visibility / user_modules.visibility */
    public static final String VISIBILITY = "^(public|internal)$";
    /** federation_modules.circuit_state */
    public static final String CIRCUIT_STATE = "^(closed|open|half)$";
    /** moderation_requests.kind */
    public static final String MODERATION_KIND = "^(instance-block|user-removal)$";
    /** moderation_requests.status */
    public static final String MODERATION_STATUS = "^(recommended|referred|approved|denied)$";
    /** federation_override.scope */
    public static final String OVERRIDE_SCOPE = "^(all|role|user)$";
    /** federation_override.action */
    public static final String OVERRIDE_ACTION = "^(circuit-break|unpublish|remove)$";
}
