package systems.snapdragon.federation.service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ScopeKind;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;
import systems.snapdragon.commons.security.PrincipalDomain;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * The kill-switch. Applies a {@link FederationOverride} to the targeted module
 * AND records the override row for audit. The override verb maps to a mutation
 * of the {@code federation_modules} read-path fields, so the change takes effect
 * on the very next manifest render (no redeploy):
 *
 * <ul>
 *   <li>{@code circuit-break} -> {@code circuit_state='open'} (manifest drops it)</li>
 *   <li>{@code unpublish}     -> {@code enabled=false}</li>
 *   <li>{@code remove}        -> hard-delete the module</li>
 * </ul>
 *
 * <p>An override has TWO effects, both audited on the one row:
 *
 * <ul>
 *   <li><b>Per-module mutation</b> (unchanged): the targeted {@code moduleSlug}'s
 *       read-path fields are mutated (circuit_state / enabled, or hard-delete), so
 *       the manifest's enabled+circuit DB finder drops it on the next render.</li>
 *   <li><b>Scope-override active row</b> (changeset 014): the row's
 *       {@code scope}/{@code target} describe WHO the kill applies to
 *       ({@code all} = everything; {@code user} = an owner's modules;
 *       {@code role} = modules declaring that required role). While
 *       {@code cleared_at IS NULL} the row is ACTIVE and
 *       {@link ManifestService} applies it across the whole catalogue at render
 *       time. {@link #clearScope} stamps {@code cleared_at} to rearm.</li>
 * </ul>
 *
 * <p>Audit-format note (intentional change): for scope=user|role the row's
 * {@code target} now carries the SCOPE VALUE (userId / role name) so the read path
 * has a clean key to match on; for scope=all {@code target} is NULL. Genuine
 * per-module intent still mutates the named module. This replaces the previous
 * {@code "slug@scopeValue"} fold (see README).
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <p>HTTP endpoints are secured by the gateway; the Casdoor JWT {@code roles} claim
 * maps to Spring authority strings before reaching this service. Internal-service
 * callers (admin-bff / mod-bff) call the ban path methods directly — not via HTTP.
 *
 * <pre>
 *  Caller                       │ list             │ apply / rearm / clearScope
 *                               │                  │ clearScopeBySource (HTTP)
 *  ─────────────────────────────┼──────────────────┼───────────────────────────
 *  ROLE_ADMIN                   │ own domain only  │ own domain only (cross-
 *                               │                  │ domain slug → 404)
 *  ROLE_SUPERADMIN              │ ALL brands       │ ALL brands (no domain
 *                               │                  │ predicate)
 *  Internal svc (admin-bff /    │ —                │ applyUserScope +
 *  mod-bff, no HTTP endpoint)   │                  │ clearScopeBySource(String)
 *                               │                  │ (no domain predicate;
 *                               │                  │ cross-brand suspension)
 * </pre>
 *
 * <h2>Account-states profile-ban path (foundation)</h2>
 * {@link #applyUserScope} / {@link #clearScopeBySource} are the read/write path the
 * access-suspension foundation (admin-bff / mod-bff) drives when a USER is banned:
 *
 * <ul>
 *   <li><b>No existing-module requirement.</b> Unlike {@link #apply}, which looks
 *       up a {@code federation_modules} slug and 404s when none exists,
 *       {@code applyUserScope} writes the scope=user {@code federation_override}
 *       row DIRECTLY via the repository. This FIXES the prior 404 when a banned
 *       user has never published a module: the durable row exists regardless and
 *       (a) drops every owned module from the manifest render AND (b) blocks the
 *       vanity profile read — both keyed on {@code owner_user_id} — and persists
 *       to block any FUTURE publish.</li>
 *   <li><b>Source-scoped clear.</b> The row is tagged
 *       {@code reason='access_suspension:<id>'} so {@code clearScopeBySource}
 *       (called when the suspension lifts/expires) rearms ONLY the row(s) that
 *       suspension wrote — never an unrelated manual scope=user kill an admin
 *       applied separately (which carries a NULL / different reason).</li>
 *   <li><b>Cache invalidation.</b> Both mutate {@link ManifestCache#invalidate()}
 *       so a just-banned profile is never served from a stale cached manifest.</li>
 *   <li><b>Fail-fast.</b> Both wrap the direct-repo write in
 *       {@code @CircuitBreaker(name = "federationOverride")}; the durable row is
 *       the source of truth, so the read path converges once it lands — the breaker
 *       sheds load against a wedged store rather than stalling the ban caller.</li>
 * </ul>
 *
 * @see systems.snapdragon.federation.controller.OverrideController
 * @see FederationOverrideRepository
 * @see FederationModuleRepository
 * @see FederationOverride
 * @see FederationModule
 * @see ScopeKind
 * @see ManifestService
 * @see VanityService
 * @see ManifestCache
 * @see PrincipalDomain
 */
@Service
public class OverrideService {

    /** Resilience4j breaker instance (see application.yml resilience4j config). */
    static final String CB = "federationOverride";

    private final FederationOverrideRepository overrides;
    private final FederationModuleRepository modules;
    private final ManifestCache cache;

    public OverrideService(FederationOverrideRepository overrides,
                           FederationModuleRepository modules,
                           ManifestCache cache) {
        this.overrides = overrides;
        this.modules = modules;
        this.cache = cache;
    }

    // ----- Override Audit List -----

    /**
     * Returns the override audit log scoped to the caller's domain. A per-domain
     * ROLE_ADMIN sees ONLY their own brand's override rows, ordered newest-first.
     * A ROLE_SUPERADMIN sees every row across all brands. The cut is enforced in
     * the DB query (not in code) via the appropriate repository finder.
     *
     * @param scope the caller's resolved brand predicate — carries the
     *              cryptographically-derived domain and the superadmin flag
     * @return a {@code Flux} streaming {@link FederationOverride} rows ordered by
     *         {@code ts} descending; empty when no overrides have been recorded
     *         for the caller's domain (or at all, for SUPERADMIN)
     * @see FederationOverrideRepository#findAllByOrderByTsDesc()
     * @see FederationOverrideRepository#findByDomainOrderByTsDesc(String)
     */
    public Flux<FederationOverride> list(PrincipalDomain scope) {
        return scope.superadmin()
                ? overrides.findAllByOrderByTsDesc()
                : overrides.findByDomainOrderByTsDesc(scope.domain());
    }

    // ----- Override Apply and Rearm -----

    /**
     * Applies an override verb against a named module slug in the caller's domain,
     * mutating the module's read-path fields and recording an audit row. The
     * targeted module is looked up pinned to the caller's domain so a ROLE_ADMIN
     * can NEVER circuit-break / unpublish / remove another brand's module — a
     * cross-domain slug resolves to 404. ROLE_SUPERADMIN targets any module across
     * all brands. The audit row is stamped with the resolved domain of the targeted
     * module (see {@link #rowDomain}).
     *
     * <p>The two effects applied atomically in sequence:
     * <ol>
     *   <li>Module row mutation via {@link #applyToModule} (circuit_state, enabled,
     *       or hard-delete) — takes effect on the next manifest render.</li>
     *   <li>Override audit row written via {@link #recordOverride} with scope,
     *       target, action, setBy, domain, and ts.</li>
     * </ol>
     *
     * @param moduleSlug  the unique slug identifying the target module
     * @param scope       the scope of the kill ({@code all | user | role}); see
     *                    {@link ScopeKind} for the valid vocabulary
     * @param scopeValue  the scope-value to store as the override target: the
     *                    owner userId for {@code scope=user}, the role name for
     *                    {@code scope=role}, or {@code null} / blank for
     *                    {@code scope=all} (target stored as NULL)
     * @param action      the override verb: {@code circuit-break}, {@code unpublish},
     *                    or {@code remove}
     * @param setBy       the Casdoor subject of the admin applying the override
     * @param domainScope the caller's resolved brand predicate (SUPERADMIN = all brands)
     * @return a {@code Mono} emitting the saved {@link FederationOverride} audit row
     *         after the module mutation and row write both complete
     * @throws ResponseStatusException {@code 400 BAD_REQUEST} when {@code action} or
     *                                 {@code scope} is not a valid token
     * @throws ResponseStatusException {@code 404 NOT_FOUND} when no module with
     *                                 {@code moduleSlug} exists in the caller's domain
     * @see #rearm(String, PrincipalDomain)
     * @see ScopeKind
     */
    public Mono<FederationOverride> apply(String moduleSlug, String scope, String scopeValue,
                                          String action, String setBy, PrincipalDomain domainScope) {
        if (!isAction(action)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST,
                    "action must be circuit-break | unpublish | remove"));
        }
        if (!isScope(scope)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "scope must be all | role | user"));
        }
        Mono<FederationModule> found = domainScope.superadmin()
                ? modules.findBySlug(moduleSlug)
                : modules.findBySlugAndDomain(moduleSlug, domainScope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + moduleSlug)))
                .flatMap(m -> applyToModule(m, action)
                        .then(recordOverride(moduleSlug, scope, scopeValue, action, setBy,
                                rowDomain(domainScope, m))));
    }

    /**
     * Resolves the domain to stamp on the recorded override audit row. For a
     * per-domain ROLE_ADMIN the caller's own domain is used directly. For a
     * ROLE_SUPERADMIN the targeted module's own domain is used so the audit row
     * stays attributed to the brand it acted on rather than a phantom
     * {@code "default"}.
     *
     * @param scope  the caller's resolved brand predicate
     * @param target the module row that is being overridden
     * @return the domain string to write into the override row's {@code domain}
     *         column; falls back to {@code "default"} when the module has no domain
     *         set (pre-026 data)
     */
    private static String rowDomain(PrincipalDomain scope, FederationModule target) {
        if (!scope.superadmin()) return scope.domain();
        String d = target.getDomain();
        return d == null ? PrincipalDomain.forDomain("default").domain() : d;
    }

    /**
     * Mutates a module's read-path fields in accordance with the override verb and
     * persists the change. The three branches map directly to the three valid action
     * tokens:
     *
     * <ul>
     *   <li>{@code circuit-break} — sets {@code circuit_state='open'} so the
     *       manifest's DB finder excludes the module on the next render.</li>
     *   <li>{@code unpublish} — sets {@code enabled=false} so the enabled+circuit
     *       finder excludes it.</li>
     *   <li>{@code remove} — hard-deletes the module row from the repository.</li>
     * </ul>
     *
     * @param m      the module row to mutate; modified in place before saving
     * @param action the override verb ({@code circuit-break | unpublish | remove}),
     *               already validated by the caller
     * @return a {@code Mono} completing when the save (or delete) finishes; signals
     *         {@code 400 BAD_REQUEST} on an unrecognised action (defensive — the
     *         caller validates first)
     */
    private Mono<?> applyToModule(FederationModule m, String action) {
        return switch (action) {
            case "circuit-break" -> {
                m.setCircuitState("open");
                m.setUpdatedAt(Instant.now());
                yield modules.save(m);
            }
            case "unpublish" -> {
                m.setEnabled(false);
                m.setUpdatedAt(Instant.now());
                yield modules.save(m);
            }
            case "remove" -> modules.delete(m);
            default -> Mono.error(new ResponseStatusException(BAD_REQUEST, "unknown action: " + action));
        };
    }

    /**
     * Builds and saves the {@link FederationOverride} audit row that records the
     * override event. The {@code target} column is set via {@link #scopeForTarget}
     * to the read-path match key the manifest and vanity resolvers will key on:
     * NULL for {@code scope=all}, the scope value for {@code scope=user|role}.
     *
     * @param moduleSlug  slug of the mutated module (used as fallback target when no
     *                    explicit scope value is provided)
     * @param scope       the scope token ({@code all | user | role})
     * @param scopeValue  the caller-supplied scope value (userId or role name), or
     *                    null / blank
     * @param action      the override verb
     * @param setBy       the Casdoor subject of the admin applying the override
     * @param domain      the resolved domain to stamp on the row (from
     *                    {@link #rowDomain})
     * @return a {@code Mono} emitting the saved {@link FederationOverride} row
     */
    private Mono<FederationOverride> recordOverride(String moduleSlug, String scope, String scopeValue,
                                                    String action, String setBy, String domain) {
        FederationOverride o = new FederationOverride();
        o.setScope(scope);
        // The active scope-override row's target is the read-path match KEY:
        //   scope=all  -> NULL (matches every module — global kill)
        //   scope=user -> the owner userId (matched vs module.owner_user_id)
        //   scope=role -> the role name  (matched vs module metadata requiresRole)
        // (the named moduleSlug is still mutated above for genuine per-slug intent).
        o.setTarget(scopeForTarget(scope, moduleSlug, scopeValue));
        o.setAction(action);
        o.setSetBy(setBy);
        // DOMAIN stamp (changeset 026): the brand this kill applies to, so the
        // manifest read path applies it ONLY to that brand's render (a scope=all kill
        // in brand X never blanks brand Y's manifest).
        o.setDomain(domain);
        o.setTs(Instant.now());
        // clearedAt stays NULL => the scope override is ACTIVE (changeset 014).
        return overrides.save(o);
    }

    /**
     * Resolves the value to store in the override row's {@code target} column,
     * following the Decision-1 target rule. For {@code scope=all} the target is
     * NULL (the global-kill row has no per-key match; scope alone is sufficient).
     * For {@code scope=user|role} the target is the explicit scope value when
     * provided, or the module slug as a fallback when the caller omitted it
     * (genuine per-slug intent with a scope annotation).
     *
     * @param scope       the scope token ({@code all | user | role})
     * @param moduleSlug  the slug of the mutated module (fallback target)
     * @param scopeValue  the caller-supplied scope value (userId or role name), or
     *                    null / blank
     * @return {@code null} for {@code scope=all}; the explicit scope value, or
     *         {@code moduleSlug} as fallback, for {@code scope=user|role}
     * @see ScopeKind
     */
    private static String scopeForTarget(String scope, String moduleSlug, String scopeValue) {
        if (ScopeKind.ALL == ScopeKind.fromWire(scope)) {
            return null;
        }
        return (scopeValue == null || scopeValue.isBlank()) ? moduleSlug : scopeValue;
    }

    /**
     * Re-arms a circuit-broken module in the caller's domain (admin recovery path):
     * flips {@code circuit_state} back to {@code "closed"} and re-enables the
     * module so it reappears on the next manifest render. The module is looked up
     * pinned to the caller's domain so a ROLE_ADMIN can NEVER re-arm another
     * brand's module — a cross-domain slug resolves to 404. ROLE_SUPERADMIN
     * re-arms any module across all brands.
     *
     * @param moduleSlug  the unique slug of the module to re-arm
     * @param domainScope the caller's resolved brand predicate (SUPERADMIN = all brands)
     * @return a {@code Mono} emitting the saved {@link FederationModule} with
     *         {@code circuitState="closed"} and {@code enabled=true}
     * @throws ResponseStatusException {@code 404 NOT_FOUND} when no module with
     *                                 {@code moduleSlug} exists in the caller's domain
     * @see #apply(String, String, String, String, String, PrincipalDomain)
     */
    public Mono<FederationModule> rearm(String moduleSlug, PrincipalDomain domainScope) {
        Mono<FederationModule> found = domainScope.superadmin()
                ? modules.findBySlug(moduleSlug)
                : modules.findBySlugAndDomain(moduleSlug, domainScope.domain());
        return found
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + moduleSlug)))
                .flatMap(m -> {
                    m.setCircuitState("closed");
                    m.setEnabled(true);
                    m.setUpdatedAt(Instant.now());
                    return modules.save(m);
                });
    }

    // ----- Scope Override Clear -----

    /**
     * Rearms a catalogue-level scope override (recovery for an {@code all},
     * {@code user}, or {@code role} kill): stamps {@code cleared_at} on every
     * matching active row so the manifest read path stops suppressing the affected
     * modules on the next render. For {@code scope=all} the target is NULL and the
     * key is scope alone; for {@code scope=user|role} the finder keys on both
     * scope and target.
     *
     * <p>DOMAIN-scoped: a ROLE_ADMIN clears ONLY active rows in their own brand —
     * the matched stream is filtered to {@code domainScope.domain()} in code so a
     * brand-X admin can never rearm a brand-Y kill. ROLE_SUPERADMIN clears matching
     * rows in every brand. Scope kills are render-time only (no module row
     * mutation), so clearing the active row is sufficient to restore; per-module
     * recovery uses {@link #rearm(String, PrincipalDomain)}.
     *
     * @param scope       the scope token to match ({@code all | user | role});
     *                    validated against {@link ScopeKind}
     * @param target      the scope value to match ({@code null} / blank is accepted
     *                    for {@code scope=all}; for {@code user|role} it identifies
     *                    the userId or role name whose kill rows to clear)
     * @param domainScope the caller's resolved brand predicate (SUPERADMIN = all brands)
     * @return a {@code Mono} emitting the count of override rows that were cleared
     *         (stamped with {@code cleared_at}); zero when no active matching rows
     *         exist in the caller's domain
     * @throws ResponseStatusException {@code 400 BAD_REQUEST} when {@code scope} is
     *                                 not a valid token
     * @see #rearm(String, PrincipalDomain)
     * @see FederationOverrideRepository#findByScopeAndClearedAtIsNull(String)
     * @see FederationOverrideRepository#findByScopeAndTargetAndClearedAtIsNull(String, String)
     */
    public Mono<Long> clearScope(String scope, String target, PrincipalDomain domainScope) {
        if (!isScope(scope)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "scope must be all | role | user"));
        }
        // scope=all carries a NULL target, so it keys on scope alone; user/role key on
        // scope+target. The branch test routes through ScopeKind; the value handed to
        // the finder is still the identical lowercase token.
        Flux<FederationOverride> active = ScopeKind.ALL == ScopeKind.fromWire(scope)
                ? overrides.findByScopeAndClearedAtIsNull(ScopeKind.ALL.value())
                : overrides.findByScopeAndTargetAndClearedAtIsNull(scope, target);
        Instant now = Instant.now();
        return active
                .filter(o -> domainScope.superadmin() || matchesDomain(o, domainScope.domain()))
                .flatMap(o -> {
                    o.setClearedAt(now);
                    return overrides.save(o);
                })
                .count();
    }

    /**
     * Tests whether an override row belongs to the given domain. Used in-code to
     * enforce the per-domain admin scope after the repository returns rows (the
     * {@code clearScope} active-row stream is not domain-pinned at the DB level for
     * the {@code scope=all} case). A row with a NULL domain (pre-026 data) is
     * treated as {@code "default"} so legacy rows remain clearable by a
     * default-domain admin (single-issuer back-compat).
     *
     * @param o      the override row to test
     * @param domain the caller's resolved domain string
     * @return {@code true} iff the row's domain (or {@code "default"} when NULL)
     *         equals {@code domain}
     */
    private static boolean matchesDomain(FederationOverride o, String domain) {
        String d = o.getDomain() == null ? PrincipalDomain.forDomain("default").domain() : o.getDomain();
        return d.equals(domain);
    }

    // ----- Account-States Profile-Ban Path (Foundation) -----

    /**
     * Apply a scope=user override DIRECTLY (the access-suspension profile-ban
     * write). Unlike {@link #apply} there is NO module lookup and NO existing-module
     * requirement — the durable {@code federation_override} row is written straight
     * to the repository, which is exactly what FIXES the prior 404 when the banned
     * user has never published a module. The row:
     *
     * <ul>
     *   <li>has {@code scope='user'} + {@code target=<ownerUsername>} — matched at
     *       manifest render against {@code module.owner_user_id} (drops every owned
     *       module) and by the vanity resolve's owner-ban check;</li>
     *   <li>is tagged {@code reason=<source>} (e.g. {@code 'access_suspension:<id>'})
     *       so {@link #clearScopeBySource} can rearm ONLY this row;</li>
     *   <li>has {@code cleared_at=NULL} (ACTIVE).</li>
     * </ul>
     *
     * <p>{@code ownerUsername} is the value stored in {@code owner_user_id}
     * (username / localpart), NOT the Casdoor sub — the vanity profile pins identity
     * on {@code owner_user_id}, so the ban must key on the same field. After the
     * write the manifest cache is invalidated so a just-banned profile is never
     * served stale.
     *
     * <p>Wrapped in {@code @CircuitBreaker} (fail-fast): the durable row is the
     * source of truth, so the read path converges once it lands; the breaker sheds
     * load against a wedged override store rather than stalling the ban caller.
     *
     * <p>This overload is the BACK-COMPAT / LEGACY entry-point (single-issuer, no
     * domain in scope). It delegates to the domain-scoped overload landing the row in
     * the {@code "default"} domain. Callers that do have a resolved domain MUST use
     * the domain-scoped overload directly.
     *
     * @param ownerUsername the {@code owner_user_id} value to ban (username / localpart)
     * @param action        the override verb ({@code unpublish} for a profile ban —
     *                       there is no ROLE_USER self-publish endpoint today, so the
     *                       ban is unpublish / vanity-suppress only)
     * @param setBy         the Casdoor subject (or service identity) applying the ban
     * @param source        the SOURCE tag, e.g. {@code 'access_suspension:<id>'}
     * @return a {@code Mono} emitting the saved {@link FederationOverride} audit row
     *         after the cache is invalidated
     * @throws ResponseStatusException {@code 400 BAD_REQUEST} when any required
     *                                 parameter is blank or {@code action} is invalid
     * @see #applyUserScope(String, String, String, String, PrincipalDomain)
     * @see #clearScopeBySource(String)
     */
    @CircuitBreaker(name = CB)
    public Mono<FederationOverride> applyUserScope(String ownerUsername, String action,
                                                   String setBy, String source) {
        // Back-compat overload: single-issuer / legacy callers land the row in the
        // 'default' domain (matches their DOMAIN_default principals + pre-026 rows).
        return applyUserScope(ownerUsername, action, setBy, source, PrincipalDomain.forDomain("default"));
    }

    /**
     * DOMAIN-scoped variant of {@link #applyUserScope(String, String, String, String)}:
     * stamps the ban row with the suspending principal's domain so a brand-X
     * suspension drops only brand-X manifests. SUPERADMIN-issued suspensions land in
     * the {@code "default"} domain (cross-brand suspension is a later admin-tooling
     * concern; the foundation never lets a ban silently apply to every brand).
     *
     * @param ownerUsername the {@code owner_user_id} value to ban (username / localpart)
     * @param action        the override verb ({@code unpublish} for a profile ban)
     * @param setBy         the Casdoor subject (or service identity) applying the ban
     * @param source        the SOURCE tag, e.g. {@code 'access_suspension:<id>'}
     * @param domainScope   the caller's resolved brand predicate; SUPERADMIN writes
     *                      land in the {@code "default"} domain (see
     *                      {@link #domainForWrite})
     * @return a {@code Mono} emitting the saved {@link FederationOverride} audit row
     *         after the cache is invalidated
     * @throws ResponseStatusException {@code 400 BAD_REQUEST} when any required
     *                                 parameter is blank or {@code action} is invalid
     * @see #applyUserScope(String, String, String, String)
     * @see ManifestCache#invalidate()
     */
    @CircuitBreaker(name = CB)
    public Mono<FederationOverride> applyUserScope(String ownerUsername, String action,
                                                   String setBy, String source, PrincipalDomain domainScope) {
        if (ownerUsername == null || ownerUsername.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "ownerUsername is required"));
        }
        if (!isAction(action)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST,
                    "action must be circuit-break | unpublish | remove"));
        }
        if (source == null || source.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST,
                    "source (reason tag) is required so the row is clearable by its source"));
        }
        FederationOverride o = new FederationOverride();
        // A profile-ban is always a per-owner (scope=user) kill; the stored column
        // value is the identical lowercase "user" token (via ScopeKind).
        o.setScope(ScopeKind.USER.value());
        o.setTarget(ownerUsername.trim());
        o.setAction(action);
        o.setSetBy(setBy);
        o.setReason(source.trim());
        o.setDomain(domainForWrite(domainScope));
        o.setTs(Instant.now());
        // clearedAt stays NULL => ACTIVE. No module mutation: the scope=user row is
        // applied at render time across the catalogue (ManifestService) and gates
        // the vanity read (VanityService) — no module need exist.
        return overrides.save(o)
                // Invalidate AFTER the durable row lands so the next manifest poll
                // re-renders from Postgres (which now excludes the banned owner's
                // modules) instead of serving a stale cached body.
                .flatMap(saved -> cache.invalidate().thenReturn(saved));
    }

    /**
     * Clears (rearms) the scope override row(s) created by a specific {@code source}
     * tag (the suspension lifting or expiring). Stamps {@code cleared_at} on EVERY
     * active row whose {@code reason} equals {@code source}, and ONLY those — a
     * manual scope=user kill an admin applied separately carries a NULL or different
     * reason and is therefore never rearmed by this path. After clearing, the
     * manifest cache is invalidated so the owner's modules return on the next render.
     *
     * <p>This overload is the BACK-COMPAT / LEGACY entry-point (single-issuer, no
     * JWT domain in scope). It delegates to the domain-scoped overload with a
     * SUPERADMIN scope so the un-pinned (cross-domain) finder is used. Callers that
     * do have a resolved domain MUST use the domain-scoped overload directly.
     *
     * <p>Wrapped in {@code @CircuitBreaker} (fail-fast) for symmetry with
     * {@link #applyUserScope}.
     *
     * @param source the SOURCE tag whose rows to clear, e.g.
     *               {@code 'access_suspension:<id>'}
     * @return a {@code Mono} emitting the count of rows cleared (stamped with
     *         {@code cleared_at}); zero when no active rows carry this source tag
     * @throws ResponseStatusException {@code 400 BAD_REQUEST} when {@code source}
     *                                 is blank
     * @see #clearScopeBySource(String, PrincipalDomain)
     */
    @CircuitBreaker(name = CB)
    public Mono<Long> clearScopeBySource(String source) {
        // Back-compat overload: the internal suspension-lift caller (admin-bff / mod-bff)
        // clears by source across EVERY brand. This is the SUPERADMIN-equivalent (no
        // domain predicate) and is NOT reachable from the per-domain admin endpoint —
        // the controller always threads a resolved PrincipalDomain (see the scoped overload).
        return clearScopeBySource(source, PrincipalDomain.superadminFor(null));
    }

    /**
     * DOMAIN-scoped variant of {@link #clearScopeBySource(String)}: clears (rearms)
     * the active scope override row(s) created by a specific {@code source} tag,
     * filtered to the caller's brand so a ROLE_ADMIN can NEVER rearm another brand's
     * suspension row by guessing its source tag.
     *
     * <p>SECURITY (cross-tenant): the prior endpoint attempt called the un-scoped
     * {@link #clearScopeBySource(String)} directly, so a domain-A admin who knew /
     * guessed a domain-B {@code reason} (e.g. {@code 'access_suspension:<id>'}) could
     * clear domain-B's row — a cross-tenant authz gap. This overload mirrors
     * {@link #clearScope(String, String, PrincipalDomain)}: for a per-domain ADMIN the
     * domain-pinned repository finder ({@link FederationOverrideRepository#findByReasonAndClearedAtIsNullAndDomain})
     * is used — a brand-A admin supplying a brand-B source tag finds ZERO matching rows
     * in their own domain and clears nothing. SUPERADMIN ({@link PrincipalDomain#superadmin()})
     * uses the un-pinned finder and sees all. The cache is invalidated only after the
     * (scoped) save stream completes so the rearmed owner's modules return on the next render.
     *
     * <p>A pre-026 row with a NULL domain is treated as {@code "default"} (see
     * {@link #matchesDomain}) so a default-domain admin can still rearm legacy rows
     * (single-issuer back-compat).
     *
     * @param source      the SOURCE tag whose rows to clear, e.g.
     *                    {@code 'access_suspension:<id>'}
     * @param domainScope the caller's resolved brand predicate (SUPERADMIN = all brands)
     * @return a {@code Mono} emitting the count of rows cleared (stamped with
     *         {@code cleared_at}); zero when no active rows match within the
     *         caller's domain
     * @throws ResponseStatusException {@code 400 BAD_REQUEST} when {@code source}
     *                                 is blank
     * @see #clearScopeBySource(String)
     * @see FederationOverrideRepository#findByReasonAndClearedAtIsNull(String)
     * @see FederationOverrideRepository#findByReasonAndClearedAtIsNullAndDomain(String, String)
     */
    @CircuitBreaker(name = CB)
    public Mono<Long> clearScopeBySource(String source, PrincipalDomain domainScope) {
        if (source == null || source.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "source is required"));
        }
        String trimmed = source.trim();
        Instant now = Instant.now();
        Flux<FederationOverride> active = domainScope.superadmin()
                ? overrides.findByReasonAndClearedAtIsNull(trimmed)
                : overrides.findByReasonAndClearedAtIsNullAndDomain(trimmed, domainScope.domain());
        return active
                .flatMap(o -> {
                    o.setClearedAt(now);
                    return overrides.save(o);
                })
                .count()
                // Only touch the cache when we actually cleared something, but the
                // invalidate is cheap + best-effort either way.
                .flatMap(n -> cache.invalidate().thenReturn(n));
    }

    // ----- Helpers -----

    /**
     * Resolves the domain to stamp on a directly-written override row (the ban
     * path, where the row is built in code rather than derived from a module
     * lookup). For a per-domain principal the principal's own domain is used.
     * For a SUPERADMIN write (no domain in scope) the row lands in {@code "default"}.
     * The value is NEVER taken from a request body.
     *
     * @param scope the caller's resolved brand predicate
     * @return the domain string to write into the override row's {@code domain}
     *         column
     */
    private static String domainForWrite(PrincipalDomain scope) {
        return scope.superadmin() ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    /**
     * Returns {@code true} iff {@code a} is a valid override action token
     * ({@code circuit-break}, {@code unpublish}, or {@code remove}).
     *
     * @param a the action string to test
     * @return {@code true} iff {@code a} is one of the three recognised verbs
     */
    private static boolean isAction(String a) {
        return "circuit-break".equals(a) || "unpublish".equals(a) || "remove".equals(a);
    }

    /**
     * Returns {@code true} iff {@code s} is a valid scope token
     * ({@code all | role | user}) — routed through {@link ScopeKind} so the
     * accept/reject set is the enum, not a hand-kept string list. The validated
     * value is still the SAME lowercase string.
     *
     * @param s the scope string to test
     * @return {@code true} iff {@code s} maps to a known {@link ScopeKind} value
     * @see ScopeKind#isValid(String)
     */
    private static boolean isScope(String s) {
        return ScopeKind.isValid(s);
    }
}
