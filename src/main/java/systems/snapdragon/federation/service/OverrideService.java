package systems.snapdragon.federation.service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
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

    /**
     * DOMAIN-scoped override audit list. A per-domain admin sees ONLY their own
     * brand's overrides; SUPERADMIN sees every override across all brands. The cut is
     * enforced in the QUERY (not in code).
     */
    public Flux<FederationOverride> list(PrincipalDomain scope) {
        return scope.superadmin()
                ? overrides.findAllByOrderByTsDesc()
                : overrides.findByDomainOrderByTsDesc(scope.domain());
    }

    /**
     * Apply an override against a module slug IN THE CALLER'S DOMAIN. {@code setBy} is
     * the admin's Casdoor subject. The targeted module is looked up pinned to the
     * caller's domain, so a per-domain admin can NEVER circuit-break / unpublish /
     * remove another brand's module (a cross-domain slug -> 404). The recorded audit
     * row is stamped with the caller's domain. SUPERADMIN targets any module.
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

    /** The domain to stamp on a recorded override row: the caller's domain, or — for
     *  a SUPERADMIN action — the TARGETED MODULE's own domain (so the audit row stays
     *  attributed to the brand it acted on, not a phantom 'default'). */
    private static String rowDomain(PrincipalDomain scope, FederationModule target) {
        if (!scope.superadmin()) return scope.domain();
        String d = target.getDomain();
        return d == null ? PrincipalDomain.forDomain("default").domain() : d;
    }

    private Mono<?> applyToModule(FederationModule m, String action) {
        switch (action) {
            case "circuit-break":
                m.setCircuitState("open");
                m.setUpdatedAt(Instant.now());
                return modules.save(m);
            case "unpublish":
                m.setEnabled(false);
                m.setUpdatedAt(Instant.now());
                return modules.save(m);
            case "remove":
                return modules.delete(m);
            default:
                return Mono.error(new ResponseStatusException(BAD_REQUEST, "unknown action: " + action));
        }
    }

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

    /** Decision-1 target rule: NULL for 'all'; the scope_value for user/role; the
     *  slug only when no scope_value was given (genuine per-slug intent). */
    private static String scopeForTarget(String scope, String moduleSlug, String scopeValue) {
        if ("all".equals(scope)) {
            return null;
        }
        return (scopeValue == null || scopeValue.isBlank()) ? moduleSlug : scopeValue;
    }

    /**
     * Re-arm a circuit-broken module IN THE CALLER'S DOMAIN (admin recovery): flip
     * circuit_state back to closed. The module is loaded pinned to the caller's
     * domain so a per-domain admin can NEVER re-arm another brand's module
     * (cross-domain slug -> 404). SUPERADMIN re-arms any module.
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

    /**
     * Rearm a SCOPE override (admin recovery for an all/user/role kill): stamp
     * {@code cleared_at} on every matching active row so the manifest read path
     * stops applying it (the suppressed modules return to the next render). For
     * scope=all the target is NULL and we key on scope alone.
     *
     * <p>DOMAIN-scoped: a per-domain admin clears ONLY active rows in their own brand
     * — the matched stream is filtered to {@code domainScope.domain()} so a brand-X
     * admin can never re-arm a brand-Y kill. SUPERADMIN clears matching rows in every
     * brand. Returns the number of rows cleared. Scope kills are render-time only, so
     * clearing the row is sufficient to restore; per-module recovery still uses
     * {@link #rearm(String, PrincipalDomain)}.
     */
    public Mono<Long> clearScope(String scope, String target, PrincipalDomain domainScope) {
        if (!isScope(scope)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "scope must be all | role | user"));
        }
        Flux<FederationOverride> active = "all".equals(scope)
                ? overrides.findByScopeAndClearedAtIsNull("all")
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

    /** True iff the override row belongs to {@code domain}. A row with a NULL domain
     *  (pre-026 data) is treated as {@code "default"} so legacy rows are clearable by
     *  a default-domain admin (single-issuer back-compat). */
    private static boolean matchesDomain(FederationOverride o, String domain) {
        String d = o.getDomain() == null ? PrincipalDomain.forDomain("default").domain() : o.getDomain();
        return d.equals(domain);
    }

    // ── Account-states profile-ban path (foundation) ────────────────────────────

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
     * @param ownerUsername the {@code owner_user_id} value to ban (username / localpart)
     * @param action        the override verb ({@code unpublish} for a profile ban —
     *                       there is no ROLE_USER self-publish endpoint today, so the
     *                       ban is unpublish / vanity-suppress only)
     * @param setBy         the Casdoor subject (or service identity) applying the ban
     * @param source        the SOURCE tag, e.g. {@code 'access_suspension:<id>'}
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
        o.setScope("user");
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
     * Clear (rearm) the scope override(s) created by a specific {@code source}
     * (the suspension lifting/expiring). Stamps {@code cleared_at} on EVERY active
     * row whose {@code reason} equals {@code source}, and ONLY those — a manual
     * scope=user kill an admin applied separately carries a NULL / different reason
     * and is therefore never rearmed. After clearing, the manifest cache is
     * invalidated so the owner's modules return on the next render.
     *
     * <p>This overload is the BACK-COMPAT / LEGACY entry-point (single-issuer,
     * no JWT in scope). It delegates to the domain-scoped overload with a
     * SUPERADMIN scope so the un-pinned (cross-domain) finder is used. Callers
     * that do have a JWT MUST use the domain-scoped overload directly.
     *
     * <p>Returns the number of rows cleared. Wrapped in {@code @CircuitBreaker}
     * (fail-fast) for symmetry with {@link #applyUserScope}.
     *
     * @param source the SOURCE tag whose rows to clear, e.g. {@code 'access_suspension:<id>'}
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
     * DOMAIN-scoped variant of {@link #clearScopeBySource(String)}: clear (rearm)
     * the active scope override(s) created by a specific {@code source}, filtered to
     * the caller's brand so a per-domain admin can NEVER rearm another brand's
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
     * @param source      the SOURCE tag whose rows to clear, e.g. {@code 'access_suspension:<id>'}
     * @param domainScope the caller's resolved brand predicate (SUPERADMIN = all)
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

    /** The domain to stamp on a directly-written override row: the principal's
     *  domain, or {@code "default"} for a SUPERADMIN write (no domain in scope).
     *  NEVER taken from a request body. */
    private static String domainForWrite(PrincipalDomain scope) {
        return scope.superadmin() ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    private static boolean isAction(String a) {
        return "circuit-break".equals(a) || "unpublish".equals(a) || "remove".equals(a);
    }

    private static boolean isScope(String s) {
        return "all".equals(s) || "role".equals(s) || "user".equals(s);
    }
}
