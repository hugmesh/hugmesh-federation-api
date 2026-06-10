package systems.snapdragon.federation.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * One kill-switch / scoped-action row (table {@code federation_override}).
 *
 * <p>The scope triple ({@code all|role|user} + {@code target}) mirrors the games
 * {@code game_access} pattern; {@code action} is the override verb applied to the
 * {@code federation_modules} read path
 * ({@code circuit-break | unpublish | remove}).
 *
 * <p>{@code clearedAt} (changeset 014) is the scope-override ACTIVE lifecycle:
 * a scope={@code all|user|role} row is ACTIVE (applied at every manifest render)
 * while {@code clearedAt IS NULL}, and is cleared/rearmed once it is stamped. This
 * is how a global / per-user / per-role kill is applied across the catalogue
 * without naming a single module slug to mutate.
 */
@Table("federation_override")
public class FederationOverride {

    @Id
    private Long id;
    /** {@code 'all' | 'role' | 'user'} */
    private String scope;
    /** scope_value (NULL for 'all') AND/OR the module slug the action applies to. */
    private String target;
    /** {@code 'circuit-break' | 'unpublish' | 'remove'} */
    private String action;
    private String setBy;
    private Instant ts;
    /**
     * Scope-override active lifecycle (changeset 014): NULL = the scope override
     * is ACTIVE and applied at manifest render; non-NULL = it has been
     * cleared/rearmed. Always NULL for true per-module-slug rows (they mutate the
     * module directly, so the read path drops them via the enabled/circuit finder).
     */
    private Instant clearedAt;

    public Long getId() { return id; }
    public String getScope() { return scope; }
    public String getTarget() { return target; }
    public String getAction() { return action; }
    public String getSetBy() { return setBy; }
    public Instant getTs() { return ts; }
    public Instant getClearedAt() { return clearedAt; }

    public void setId(Long id) { this.id = id; }
    public void setScope(String scope) { this.scope = scope; }
    public void setTarget(String target) { this.target = target; }
    public void setAction(String action) { this.action = action; }
    public void setSetBy(String setBy) { this.setBy = setBy; }
    public void setTs(Instant ts) { this.ts = ts; }
    public void setClearedAt(Instant clearedAt) { this.clearedAt = clearedAt; }
}
