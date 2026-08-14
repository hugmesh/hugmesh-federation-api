package net.hugmesh.federation.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.cache.ManifestCache;
import net.hugmesh.federation.model.FederationManifestDto;
import net.hugmesh.federation.model.FederationManifestDto.FederationRemoteDto;
import net.hugmesh.federation.model.FederationModule;
import net.hugmesh.federation.model.FederationOverride;
import net.hugmesh.federation.model.ScopeKind;
import net.hugmesh.federation.repository.FederationModuleRepository;
import net.hugmesh.federation.repository.FederationOverrideRepository;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.commons.security.Roles;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Manifest read path — the keystone of the dynamic module-federation platform.
 *
 * <h2>Responsibility</h2>
 *
 * <p>Renders a {@link FederationManifestDto} for
 * {@code GET /api/federation/manifest} (see
 * {@link net.hugmesh.federation.controller.FederationController#manifest
 * FederationController.manifest}).
 * The Angular host shell calls this endpoint on bootstrap and on every full
 * reload, feeding {@code remotes[]} directly into native-federation's
 * {@code initFederation(...)} before {@code bootstrapApplication()} — so new
 * Angular micro-frontend modules appear without redeploying the host shell.
 *
 * <p>Lifted from the games {@code FederationController.manifest()} (the
 * {@code findAllByEnabledTrue → DTO → {generatedAt, remotes}} chain) and
 * extended with platform filters applied <em>in code</em> so that the same DB
 * rows serve every caller audience correctly.
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <p>The Casdoor JWT is validated by the Spring Security resource-server filter
 * before reaching this service; the JWT {@code roles} claim maps to Spring
 * authority strings (see
 * {@link net.hugmesh.federation.config.SecurityConfig SecurityConfig}).
 * Two orthogonal parameters shape the result:
 *
 * <pre>
 *  Caller                      │ visibility rows visible │ domain scope
 *  ────────────────────────────┼─────────────────────────┼──────────────────────
 *  ROLE_USER / ROLE_MOD        │ public only             │ own brand only
 *  ROLE_ADMIN / ROLE_INTERNAL  │ public + internal       │ own brand only
 *  ROLE_SUPERADMIN             │ public + internal       │ ALL brands (control
 *                              │                         │ plane — no predicate)
 * </pre>
 *
 * <p>{@code ROLE_MOD} confers no manifest privilege beyond {@code ROLE_USER}:
 * mods act in the moderation controller
 * ({@link net.hugmesh.federation.controller.ModerationController
 * ModerationController}), not here.
 *
 * <h2>Four render-time filters</h2>
 *
 * <p>The same {@code federation_modules} rows serve every audience; the caller
 * sees only what passes all four gates:
 *
 * <ol>
 *   <li><b>enabled</b> — DB-side ({@code findAllByEnabledTrue...}).  An
 *       "unpublish" override sets {@code enabled = false} on the module row
 *       at apply time (slug-scoped mutation — never in this path).</li>
 *   <li><b>circuit-state</b> — DB-side; only {@code circuit_state = 'closed'}
 *       rows are returned.  A "circuit-break" override trips a module to
 *       {@code 'open'} as a runtime kill-switch without logically disabling
 *       it (still visible to admins in the registry).</li>
 *   <li><b>visibility</b> — in code ({@link #isVisibleTo}).
 *       {@code visibility = 'public'} is visible to ALL authenticated callers;
 *       {@code visibility = 'internal'} is stripped unless the caller holds
 *       {@code ROLE_ADMIN}, {@code ROLE_INTERNAL}, or {@code ROLE_SUPERADMIN}.</li>
 *   <li><b>active scope overrides</b> — in code ({@link #isSuppressedByScope}).
 *       A {@code federation_override} row with {@code scope IN ('all','user','role')}
 *       and {@code cleared_at IS NULL} is an active catalogue-level kill that
 *       suppresses matching modules at render time without mutating any module
 *       row. These are loaded once per render, applied in code.</li>
 * </ol>
 *
 * <h2>Reactive pipeline marble diagram</h2>
 *
 * <pre>
 *  ┌─ activeScope (Flux → collectList) ──────────────────────────────────────┐
 *  │  repository: findByScopeIn(all|user|role) WHERE cleared_at IS NULL      │
 *  │  [domain-pinned for per-brand caller; un-pinned for SUPERADMIN]          │
 *  └──────────────────────────────────────┬──────────────────────────────────┘
 *                                         │  List&lt;FederationOverride&gt;
 *                                         ▼
 *  ┌─ assembleManifest(modules, active, canSeeInternal) ─────────────────────┐
 *  │                                                                         │
 *  │  modules (Flux&lt;FederationModule&gt;)                                       │
 *  │  ──── .filter(isVisibleTo)           ← 3. visibility cut               │
 *  │  ──── .filter(!isSuppressedByScope)  ← 4. scope-override kill cut      │
 *  │  ──── .map(FederationRemoteDto::from)   project to wire shape          │
 *  │  ──── .collectList()                                                    │
 *  │  ──── .map(remotes → new FederationManifestDto(now, remotes))          │
 *  └──────────────────────────────────────┬──────────────────────────────────┘
 *                                         │  FederationManifestDto
 *                                         ▼
 *  ┌─ cacheIfPublicSafe ─────────────────────────────────────────────────────┐
 *  │  write-through to ManifestCache, KEYED BY domain, ONLY when both hold:  │
 *  │    · !canSeeInternal  (no internal rows in the result)                 │
 *  │    · !superadmin      (not the cross-domain SUPERADMIN superset)       │
 *  │  Any brand's public-safe render is cacheable — under ITS OWN key — not  │
 *  │  just "default" (per-brand cache key). Any other render (internal-      │
 *  │  bearing or the SUPERADMIN superset) is returned directly — cache is    │
 *  │  never touched.                                                         │
 *  └──────────────────────────────────────┬──────────────────────────────────┘
 *                                         │
 *                                         ▼
 *                          Mono&lt;FederationManifestDto&gt;
 * </pre>
 *
 * <h2>Cache contract</h2>
 *
 * <p>The rendered manifest is written through to {@link ManifestCache}
 * (backed by
 * {@link net.hugmesh.federation.cache.CassandraManifestCache
 * CassandraManifestCache} or a no-op) so remote-fragment pods and CDN edge
 * pollers can serve a stale-but-valid view during a brief Postgres blip.
 * <b>Per-brand cache key:</b> ANY brand's <em>public-safe</em> view is cached,
 * but ONLY under that brand's own {@code domain} key — a brand-B poller can
 * never be served brand-A's cached body. Internal rows and the SUPERADMIN
 * cross-brand superset bypass the cache entirely (under any key), so an
 * anonymous poller can never be served elevated or cross-brand content from a
 * stale hit. Cache failure is swallowed (implementation contract: best-effort,
 * never throws); the authoritative Postgres render is always returned.
 *
 * <h2>Scope-override honest limitation ({@code scope=role})</h2>
 *
 * <p>There is NO per-module role column and NO user-to-role mapping in this
 * service — roles live only in the Casdoor JWT. An audience cut that filters by
 * the <em>caller's</em> roles would poison the shared cache (per-caller
 * filtering requires a per-caller cache key). Instead, {@code scope=role}
 * suppresses modules whose <em>declared</em>
 * {@code metadata.requiresRole} (case-insensitive) matches the override
 * target. This is content-based and cache-safe. It is NOT "modules owned by
 * users holding role R." See README → Deferred for the future audience-cut
 * design.
 *
 * @see net.hugmesh.federation.controller.FederationController#manifest
 * @see net.hugmesh.federation.repository.FederationModuleRepository
 * @see net.hugmesh.federation.repository.FederationOverrideRepository
 * @see ManifestCache
 * @see ScopeKind
 * @see PrincipalDomain
 * @see net.hugmesh.federation.service.OverrideService
 */
@Service
public class ManifestService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * The {@code scope IN (...)} in-clause for the active-override DB finder,
     * derived at class-load from {@link ScopeKind} so the list stays byte-identical
     * to the enum values and can never drift.  Only {@code all|user|role} scope rows
     * reach this path; per-module-slug rows mutated the DB module record at apply
     * time and are excluded by the enabled/circuit-state DB finder.
     */
    private static final List<String> SCOPE_KINDS =
            Arrays.stream(ScopeKind.values()).map(ScopeKind::value).toList();

    private final FederationModuleRepository repo;
    private final FederationOverrideRepository overrides;
    private final ManifestCache cache;

    public ManifestService(FederationModuleRepository repo,
                           FederationOverrideRepository overrides,
                           ManifestCache cache) {
        this.repo = repo;
        this.overrides = overrides;
        this.cache = cache;
    }

    // -------------------------------------------------------------------------
    // Public render API
    // -------------------------------------------------------------------------

    /**
     * Back-compat render: a caller with only authority strings (no resolved
     * domain context) renders the {@code "default"} domain's manifest —
     * single-issuer / legacy behaviour.  A SUPERADMIN authority set still gets
     * the cross-domain (all-brands) tier so the infra control plane sees every
     * remote even via this overload.
     *
     * @param authorities the caller's Spring Security authority strings (e.g.
     *                    {@code Set.of("ROLE_ADMIN", "DOMAIN_default")}); null
     *                    or empty yields a public-only, default-domain render
     * @return a {@code Mono} emitting exactly one {@link FederationManifestDto};
     *         never empty — worst case an empty {@code remotes} list
     * @see #render(Set, PrincipalDomain)
     */
    public Mono<FederationManifestDto> render(Set<String> authorities) {
        PrincipalDomain scope = (authorities != null && Roles.isSuperadminNames(authorities))
                ? PrincipalDomain.superadminFor(null)
                : PrincipalDomain.forDomain("default");
        return render(authorities, scope);
    }

    /**
     * Renders the manifest for a caller with the given authorities, scoped to
     * their brand/domain.  This is the primary entry point, called from
     * {@link net.hugmesh.federation.controller.FederationController#manifest
     * FederationController.manifest}.
     *
     * <p><b>Per-domain tier</b> (common case) — the module and active-scope-override
     * finders are pinned to {@code scope.domain()}, so a brand-X principal's
     * manifest lists ONLY brand-X remotes, and a brand-X {@code scope=all} kill
     * never blanks brand-Y.  The domain predicate is enforced in the DB query,
     * not spoofable in code.
     *
     * <p><b>SUPERADMIN tier</b> ({@code scope.superadmin() == true}) — the
     * un-pinned finders run; the cross-domain infra role sees EVERY brand's
     * remotes in one manifest (the control-plane tier).  No domain predicate.
     *
     * <p>{@code canSeeInternal} (ADMIN / INTERNAL / SUPERADMIN) controls whether
     * {@code visibility='internal'} remotes are included — orthogonal to the
     * domain cut.  Always rendered from Postgres for the per-caller-filtered
     * authoritative result; the cache is written through ONLY on the public-safe
     * DEFAULT-domain render (see {@link #isPublicSafeDefaultRender}) so it never
     * leaks internal rows or another brand's remotes to an anonymous poller.
     *
     * @param authorities the caller's Spring Security authority strings from the
     *                    validated Casdoor JWT; null or empty yields public-only
     * @param scope       the resolved tenant scope — carries the
     *                    cryptographically-derived {@code domain} and the
     *                    {@code superadmin} flag;  null collapses to a
     *                    default-domain, non-superadmin render
     * @return a {@code Mono} emitting exactly one {@link FederationManifestDto};
     *         never empty — worst case an empty {@code remotes} list
     * @see PrincipalDomain
     * @see net.hugmesh.commons.security.DomainRegistry
     */
    public Mono<FederationManifestDto> render(Set<String> authorities, PrincipalDomain scope) {
        boolean canSeeInternal = authorities != null
                && (authorities.contains("ROLE_ADMIN") || authorities.contains("ROLE_INTERNAL")
                    || Roles.isSuperadminNames(authorities));
        boolean superadmin = scope != null && scope.superadmin();
        String domain = scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();

        // Active scope-override set + module stream — pinned to the caller's domain
        // unless SUPERADMIN (un-pinned, all brands).  Loaded ONCE per render.
        Flux<FederationOverride> activeScope = superadmin
                ? overrides.findByScopeInAndClearedAtIsNull(SCOPE_KINDS)
                : overrides.findByScopeInAndClearedAtIsNullAndDomain(SCOPE_KINDS, domain);
        Flux<FederationModule> modules = superadmin
                ? repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed")
                : repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", domain);

        // Whether THIS render may be written through to the shared cache: only a
        // public-safe view (no internal rows, no cross-domain SUPERADMIN superset)
        // is cacheable, so a tokenless poller never receives internal or cross-brand
        // remotes. ANY brand qualifies — see the per-brand cache key on cacheIfPublicSafe.
        boolean cacheable = isPublicSafeRender(canSeeInternal, superadmin);

        // Linear pipeline:
        //   1. load the active scope-override set once,
        //   2. filter + assemble modules into a manifest against it,
        //   3. write-through the cache (keyed by domain) only when this render is
        //      public-safe.
        return activeScope
                .collectList()
                .flatMap(active -> assembleManifest(modules, active, canSeeInternal))
                .flatMap(manifest -> cacheIfPublicSafe(manifest, cacheable, domain));
    }

    // -------------------------------------------------------------------------
    // Pipeline stages
    // -------------------------------------------------------------------------

    /**
     * Applies the per-caller cuts to the module stream and assembles the manifest
     * DTO.  Drops {@code visibility='internal'} rows the caller may not see,
     * drops rows an active scope override suppresses, then projects the survivors
     * to wire-shape {@link FederationRemoteDto} under a fresh {@code generatedAt}
     * timestamp.
     *
     * <p>The reactive chain is intentionally flat (named method references, no
     * nested lambdas) so each step reads as a plain-English sentence:
     *
     * <pre>
     *   modules
     *     → filter(visibility cut)
     *     → filter(scope-override cut)
     *     → map(→ FederationRemoteDto)
     *     → collectList()
     *     → map(→ FederationManifestDto(generatedAt, remotes))
     * </pre>
     *
     * @param modules        reactive stream of all enabled + circuit-closed module
     *                       rows for the caller's domain (or all domains for
     *                       SUPERADMIN)
     * @param active         active scope-override rows loaded once per render;
     *                       passed in to avoid a reactive fan-out inside the
     *                       per-module filter loop
     * @param canSeeInternal {@code true} when the caller holds {@code ROLE_ADMIN},
     *                       {@code ROLE_INTERNAL}, or {@code ROLE_SUPERADMIN}
     * @return a {@code Mono<FederationManifestDto>} emitting exactly one DTO
     */
    private Mono<FederationManifestDto> assembleManifest(Flux<FederationModule> modules,
                                                         List<FederationOverride> active,
                                                         boolean canSeeInternal) {
        return modules
                // visibility cut: internal rows only for admin/internal callers
                .filter(m -> isVisibleTo(m, canSeeInternal))
                // active scope-override cut: drop any module a live kill-switch matches
                .filter(m -> !isSuppressedByScope(m, active))
                // project each surviving module row to its public remote descriptor
                .map(FederationRemoteDto::from)
                .collectList()
                // stamp the render time and wrap the remotes into the manifest body
                .map(remotes -> new FederationManifestDto(Instant.now().toString(), remotes));
    }

    /**
     * Best-effort write-through: a public-safe render for {@code domain} is stored
     * UNDER THAT DOMAIN'S OWN cache key so a tokenless poller / CDN edge can serve
     * it. Every other render — internal-bearing or the SUPERADMIN cross-domain
     * superset — is returned WITHOUT touching the cache so it can never leak
     * privileged or cross-brand content.
     *
     * <p>Per-brand cache key: {@code domain} is threaded straight into
     * {@link ManifestCache#put}, so brand-A and brand-B renders occupy distinct
     * cache rows and can never shadow one another. Cache failure is swallowed
     * inside {@link ManifestCache} (implementation contract: best-effort, never
     * throws), so a cache outage never breaks the read path.
     *
     * @param manifest  the freshly rendered manifest to (maybe) cache
     * @param cacheable {@code true} iff this render is public-safe (see
     *                  {@link #isPublicSafeRender})
     * @param domain    the resolved domain this render targeted — the cache key
     *                  when {@code cacheable}
     * @return a {@code Mono} emitting {@code manifest} after the optional cache
     *         write completes, or immediately when not cacheable
     */
    private Mono<FederationManifestDto> cacheIfPublicSafe(FederationManifestDto manifest, boolean cacheable,
                                                           String domain) {
        if (cacheable) {
            return cache.put(domain, manifest).thenReturn(manifest);
        }
        return Mono.just(manifest);
    }

    // -------------------------------------------------------------------------
    // Filter predicates
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} iff this render may be written to the shared cache
     * (under its own domain's key — see {@link #cacheIfPublicSafe}).
     * A render is public-safe when:
     * <ul>
     *   <li>it carries no {@code visibility='internal'} rows
     *       ({@code !canSeeInternal}), and</li>
     *   <li>it is not the SUPERADMIN cross-domain superset
     *       ({@code !superadmin}).</li>
     * </ul>
     * ANY brand's domain qualifies — the per-brand cache key means a brand-B
     * public render can be cached under brand-B's own row without ever being
     * confused with brand-A's. Violating either condition risks poisoning the
     * cache for anonymous pollers with elevated or cross-brand content.
     *
     * @param canSeeInternal {@code true} when the caller holds {@code ROLE_ADMIN},
     *                       {@code ROLE_INTERNAL}, or {@code ROLE_SUPERADMIN}
     * @param superadmin     {@code true} when the caller is the cross-domain
     *                       infra role
     * @return {@code true} iff the rendered manifest is safe to cache publicly
     */
    private static boolean isPublicSafeRender(boolean canSeeInternal, boolean superadmin) {
        return !canSeeInternal && !superadmin;
    }

    /**
     * Visibility/role cut — returns {@code true} iff the given module is visible
     * to a caller at the given access level.
     *
     * <ul>
     *   <li>{@code visibility = 'public'} (or any null / unrecognised value) —
     *       visible to ALL authenticated callers (ROLE_USER, ROLE_MOD, ROLE_ADMIN,
     *       ROLE_SUPERADMIN).</li>
     *   <li>{@code visibility = 'internal'} — visible ONLY to callers holding
     *       {@code ROLE_ADMIN}, {@code ROLE_INTERNAL}, or {@code ROLE_SUPERADMIN}
     *       ({@code canSeeInternal = true}).</li>
     * </ul>
     *
     * <p>A null or unrecognised visibility value defaults to {@code 'public'}:
     * fail-open for unknown future values so a mis-typed field never silently hides
     * a module from every caller.
     *
     * @param m              the module row to test
     * @param canSeeInternal {@code true} when the caller holds {@code ROLE_ADMIN},
     *                       {@code ROLE_INTERNAL}, or {@code ROLE_SUPERADMIN}
     * @return {@code true} iff {@code m} should appear in the caller's manifest
     */
    static boolean isVisibleTo(FederationModule m, boolean canSeeInternal) {
        String v = m.getVisibility() == null ? "public" : m.getVisibility();
        if ("internal".equalsIgnoreCase(v)) {
            return canSeeInternal;
        }
        return true; // 'public' (or any other value) is visible to everyone
    }

    /**
     * Active-scope-override cut — returns {@code true} iff the given module is
     * suppressed (dropped from the manifest) by at least one active scope override.
     *
     * <p>Scope semantics:
     *
     * <pre>
     *  scope   │ target (override.target)            │ matches when
     *  ────────┼─────────────────────────────────────┼───────────────────────────
     *  all     │ NULL                                │ EVERY module — global kill
     *  user    │ Casdoor subject of the killed owner │ module.ownerUserId equals target
     *  role    │ role name (e.g. "admin")            │ module.metadata.requiresRole
     *          │                                     │ equals target (case-insensitive)
     * </pre>
     *
     * <p><b>Who creates active scope overrides</b>:
     * <ul>
     *   <li><b>Admin / Superadmin via API</b>
     *       ({@code POST /api/federation/overrides}) — manual kill;
     *       {@code set_by} = admin subject, {@code reason = NULL}.</li>
     *   <li><b>Account-states / access-suspension path</b> — writes
     *       {@code reason = 'access_suspension:&lt;id&gt;'} so the ban can be cleared
     *       precisely via
     *       {@link net.hugmesh.federation.service.OverrideService#clearScopeBySource
     *       OverrideService.clearScopeBySource} when the suspension expires, without
     *       accidentally clearing an unrelated admin kill.</li>
     * </ul>
     *
     * <p>The {@code action} verb ({@code circuit-break | unpublish | remove}) is
     * informational at this stage: ANY active scope row ({@code cleared_at IS NULL})
     * suppresses matched modules regardless of verb.  Per-module-slug overrides are
     * NOT in {@code active} — they mutated the module row at apply time and are
     * excluded by the enabled/circuit-state DB finder before this method is reached.
     *
     * @param m      the module row to test
     * @param active all currently active scope-override rows for the caller's domain
     *               (loaded once per render, not re-queried per module)
     * @return {@code true} iff {@code m} should be dropped from the manifest
     * @see ScopeKind
     * @see net.hugmesh.federation.service.OverrideService
     */
    static boolean isSuppressedByScope(FederationModule m, List<FederationOverride> active) {
        for (FederationOverride o : active) {
            if (matches(m, o)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests whether a single active scope-override row suppresses the given module.
     * Routes the scope string through {@link ScopeKind#fromWire(String)} so the
     * branching is exhaustive and typo-proof via a sealed {@code switch}.
     * An unknown or null scope returns {@code false} (matches nothing), preserving
     * the prior {@code "all".equals(scope)} fall-through behaviour.
     *
     * @param m the module row to test
     * @param o the active scope-override row to test against
     * @return {@code true} iff {@code o} suppresses {@code m}
     */
    private static boolean matches(FederationModule m, FederationOverride o) {
        // Route the closed all|user|role vocabulary through the ScopeKind enum. The
        // stored value is the SAME lowercase string; fromWire is a null-tolerant lens
        // (an unknown/null scope → null → "matches nothing", exactly the prior
        // string-equals fall-through behaviour). No DB/JSON value changes.
        ScopeKind kind = ScopeKind.fromWire(o.getScope());
        if (kind == null) {
            return false;
        }
        return switch (kind) {
            // scope=all matches EVERY module (global kill — the override's target is NULL).
            case ALL -> true;
            // scope=user matches when the module's owner equals the override target.
            case USER -> m.getOwnerUserId() != null && m.getOwnerUserId().equals(o.getTarget());
            // scope=role matches when the module's declared requiresRole equals the target
            // (case-insensitive).
            case ROLE -> {
                String required = requiresRole(m.getMetadata());
                yield required != null && o.getTarget() != null
                        && required.equalsIgnoreCase(o.getTarget());
            }
        };
    }

    // -------------------------------------------------------------------------
    // Metadata helpers
    // -------------------------------------------------------------------------

    /**
     * Null-safe parse of the module's declared required role from its
     * {@code metadata} JSON blob ({@code {"requiresRole":"admin"}} convention).
     * Pure CPU, no blocking I/O — safe on the reactive scheduler thread.
     *
     * <p>Returns {@code null} in all failure cases (null/blank metadata string,
     * malformed JSON, absent or non-textual {@code requiresRole} field).  The
     * exception is swallowed intentionally: metadata is optional / admin-supplied,
     * so a bad JSON blob must never break the manifest read path.
     *
     * @param metadata the raw JSON string from
     *                 {@link FederationModule#getMetadata()}, or {@code null}
     * @return the declared role name (e.g. {@code "admin"}), or {@code null}
     *         when absent / unparseable
     */
    static String requiresRole(String metadata) {
        if (metadata == null || metadata.isBlank()) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(metadata);
            JsonNode rr = node.get("requiresRole");
            return (rr != null && rr.isTextual()) ? rr.asText() : null;
        } catch (Exception e) {
            return null; // malformed metadata never breaks the read path
        }
    }

    // -------------------------------------------------------------------------
    // Admin / test helpers
    // -------------------------------------------------------------------------

    /**
     * Returns all enabled + circuit-closed ({@code circuit_state = 'closed'})
     * module rows across ALL domains (no domain predicate), ordered by kind then
     * slug.  Used by integration tests and admin tooling that need to inspect the
     * full registry state — NOT the caller-filtered manifest render path (use
     * {@link #render(Set, PrincipalDomain)} for that).
     *
     * @return a {@code Flux} streaming every active module row; empty when none
     *         are registered or all are disabled / circuit-open
     */
    public Flux<FederationModule> activeModules() {
        return repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed");
    }
}
