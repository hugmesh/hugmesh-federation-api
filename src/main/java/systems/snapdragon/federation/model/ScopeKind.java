package systems.snapdragon.federation.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of {@code federation_override.scope} kinds — the WHO a
 * scoped kill-switch applies to. This is a genuinely CLOSED vocabulary: it is
 * pinned by the 018 DB CHECK constraint, the {@code OVERRIDE_SCOPE} bean-validation
 * regex, and the legacy {@code isScope} guard, all of which accept exactly
 * {@code all | user | role}.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String} ("all"/"user"/"role")</h2>
 * Each constant carries the EXACT lowercase token the system has always stored /
 * exchanged:
 * <ul>
 *   <li><b>DB</b> — the {@code federation_override.scope varchar} column keeps its
 *       lowercase strings. The entity ({@link FederationOverride#getScope()}) still
 *       persists a {@code String}, so R2DBC reads/writes are unchanged; this enum is
 *       a CODE-SIDE lens over that string, never a column type change.</li>
 *   <li><b>JSON</b> — {@link #value()} is annotated {@link JsonValue}, so anywhere an
 *       enum value were serialized it emits the lowercase token (not the Java
 *       constant name); {@link #fromWire(String)} (also a {@link JsonCreator}) parses
 *       the same tokens back. The request DTOs still bind {@code scope} as a
 *       {@code String}, so this is not on any current JSON path — but the round-trip
 *       is wire-safe by construction.</li>
 * </ul>
 *
 * <p>Routing the scope branching ({@code isSuppressedByScope}, the apply / clear
 * paths) through this enum replaces the scattered {@code "all".equals(scope)} string
 * literals with an exhaustive, typo-proof {@code switch}, WITHOUT changing a single
 * stored or transmitted value.
 */
public enum ScopeKind {

    /** Global kill — matches EVERY module (the override carries a NULL target). */
    ALL("all"),
    /** Per-owner kill — matches modules whose {@code owner_user_id} equals the target. */
    USER("user"),
    /** Per-role kill — matches modules whose declared {@code metadata.requiresRole} equals the target. */
    ROLE("role");

    private final String value;

    ScopeKind(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code all | user | role}) — the DB/JSON form. */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token ({@code all | user | role}) to its {@link ScopeKind}, or
     * {@code null} when the token is null / unrecognised. Null-tolerant by design:
     * the read path ({@code ManifestService.matches}) treats an unknown / null scope
     * as "matches nothing", so it never throws on a stray row — exactly the prior
     * {@code "all".equals(scope)} fall-through behaviour.
     */
    @JsonCreator
    public static ScopeKind fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (ScopeKind k : values()) {
            if (k.value.equals(wire)) {
                return k;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the three valid scope tokens. The typed
     * equivalent of the legacy {@code isScope(String)} guard, kept so callers that
     * still hold a raw {@code String} (the controller validation already ran, the
     * service double-checks) get the same accept/reject verdict.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
