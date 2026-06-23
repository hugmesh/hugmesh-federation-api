package systems.snapdragon.federation.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.cache.ManifestCache;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationManifestDto.FederationRemoteDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ScopeKind;
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.commons.security.Roles;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * The federation manifest read path — the platform keystone.
 *
 * <p>Lifted from the games {@code FederationController.manifest()}
 * (findAllByEnabledTrue -> DTO -> {generatedAt, remotes}) and extended with the
 * three platform filters applied IN CODE against the caller (so the same DB rows
 * serve every audience, filtered per request):
 *
 * <ul>
 *   <li><b>enabled</b>  — DB-side ({@code findAllByEnabledTrue...}); an
 *       unpublish override flips {@code enabled=false}.</li>
 *   <li><b>circuit-state</b> — only {@code circuit_state='closed'} rows ship;
 *       a circuit-break override flips it to {@code 'open'} so the remote drops
 *       from the manifest without a redeploy (kill-switch).</li>
 *   <li><b>visibility / role</b> — {@code visibility='public'} rows are visible
 *       to everyone; {@code visibility='internal'} rows only to callers holding
 *       {@code ROLE_ADMIN} (or {@code ROLE_INTERNAL}). The host enforces
 *       per-remote route access too; this is the catalog-level cut.</li>
 *   <li><b>active scope overrides</b> — a scope={@code all|user|role}
 *       {@code federation_override} that has NOT been rearmed
 *       ({@code cleared_at IS NULL}) is applied across the WHOLE catalogue at
 *       render time (these have no single module slug to mutate, so they cannot
 *       ride the DB finder). See {@link #isSuppressedByScope}.</li>
 * </ul>
 *
 * <p><b>scope=role semantics (honest limitation).</b> There is NO module role
 * column and NO user→role table in this service (roles live only in the Casdoor
 * JWT). An AUDIENCE cut (filter by the caller's roles) is rejected because the
 * manifest cache stores a single public-safe view and per-caller filtering would
 * poison it. So scope=role suppresses modules whose DECLARED required role
 * ({@code metadata.requiresRole}, case-insensitive) equals the target role. This
 * is content-based (cache-safe) and uses data already present in the seed. It is
 * NOT "modules owned by users holding role R" (no owner→role source exists). See
 * README → Deferred.
 *
 * <p>The rendered manifest is write-through cached (best-effort) so the
 * remote-fragment pods / edge can poll it; a cache miss / failure always renders
 * from Postgres. The scope cut runs on the SAME public-safe stream, so the cache
 * keeps storing only the public-safe (now also scope-filtered) view.
 */
@Service
public class ManifestService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * The scope kinds applied at render time (not via per-module mutation), as the
     * lowercase wire tokens the {@code scope IN (...)} DB finder expects. DERIVED from
     * {@link ScopeKind} so the in-clause can never drift from the enum, while the
     * actual values passed to R2DBC stay the identical {@code [all, user, role]}.
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

    /**
     * Back-compat render: a caller with only authorities (no domain context) renders
     * the {@code "default"} domain's manifest (single-issuer / legacy behaviour). A
     * SUPERADMIN authority set still gets the cross-domain (all-brands) tier so the
     * infra control plane sees every remote even via this overload.
     */
    public Mono<FederationManifestDto> render(Set<String> authorities) {
        PrincipalDomain scope = (authorities != null && Roles.isSuperadminNames(authorities))
                ? PrincipalDomain.superadminFor(null)
                : PrincipalDomain.forDomain("default");
        return render(authorities, scope);
    }

    /**
     * Render the manifest for a caller with the given authorities, scoped to their
     * brand/domain. Two tiers:
     *
     * <ul>
     *   <li><b>PER-DOMAIN</b> (the common case) — the module + active-scope-override
     *       finders are pinned to {@code scope.domain()}, so a brand-X principal's
     *       manifest lists ONLY brand-X remotes and a brand-X scope=all kill never
     *       blanks brand-Y. This is the per-domain CUT, enforced in the QUERY.</li>
     *   <li><b>SUPERADMIN</b> ({@code scope.superadmin()}) — the un-pinned finders
     *       run, so the cross-domain infra role sees EVERY brand's remotes in one
     *       manifest (the control-plane tier). No domain predicate.</li>
     * </ul>
     *
     * <p>{@code canSeeInternal} (ADMIN/INTERNAL) still controls whether
     * {@code internal}-visibility remotes are included — orthogonal to the domain
     * cut. Always rendered from Postgres for the authoritative, per-caller-filtered
     * result; the cache is written through ONLY on the public-safe DEFAULT-domain
     * render (see below) so it never leaks internal rows NOR another brand's remotes
     * to an anonymous poller.
     */
    public Mono<FederationManifestDto> render(Set<String> authorities, PrincipalDomain scope) {
        boolean canSeeInternal = authorities != null
                && (authorities.contains("ROLE_ADMIN") || authorities.contains("ROLE_INTERNAL")
                    || Roles.isSuperadminNames(authorities));
        boolean superadmin = scope != null && scope.superadmin();
        String domain = scope == null ? PrincipalDomain.forDomain("default").domain() : scope.domain();

        // Active scope-override set + module stream — pinned to the caller's domain
        // unless SUPERADMIN (un-pinned, all brands). Loaded ONCE per render.
        Flux<FederationOverride> activeScope = superadmin
                ? overrides.findByScopeInAndClearedAtIsNull(SCOPE_KINDS)
                : overrides.findByScopeInAndClearedAtIsNullAndDomain(SCOPE_KINDS, domain);
        Flux<FederationModule> modules = superadmin
                ? repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed")
                : repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", domain);

        // Whether THIS render may be written through to the shared cache: only the
        // public-safe DEFAULT-domain view (no internal rows, no cross-domain superset)
        // is cacheable, so a tokenless poller never sees internal/other-brand remotes.
        boolean cacheable = isPublicSafeDefaultRender(canSeeInternal, superadmin, domain);

        // Linear pipeline (was a 4-level nested lambda):
        //   1. load the active scope-override set once,
        //   2. filter+assemble the modules into a manifest against it,
        //   3. write-through the cache only when this render is public-safe.
        return activeScope
                .collectList()
                .flatMap(active -> assembleManifest(modules, active, canSeeInternal))
                .flatMap(manifest -> cacheIfPublicSafe(manifest, cacheable));
    }

    /**
     * Apply the per-caller cuts to the module stream and assemble the manifest DTO:
     * drop internal rows the caller may not see (visibility cut), drop rows an ACTIVE
     * scope override suppresses (kill-switch cut), then project the survivors to
     * remote DTOs under a fresh {@code generatedAt}. Behaviour is identical to the
     * prior inline chain; only the nesting is gone.
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
     * Best-effort write-through: a public-safe DEFAULT-domain render is stored so a
     * tokenless poller can serve it; every other render (internal-bearing, superadmin
     * cross-domain, or a brand-specific view) is returned WITHOUT touching the cache
     * so it can never leak. A per-brand cache key is a later enhancement — until then
     * only the canonical default public view is ever cached. Cache failure is
     * swallowed inside the cache, so this never breaks the read path.
     */
    private Mono<FederationManifestDto> cacheIfPublicSafe(FederationManifestDto manifest, boolean cacheable) {
        if (cacheable) {
            return cache.put(manifest).thenReturn(manifest);
        }
        return Mono.just(manifest);
    }

    /** A render is public-safe (cacheable) iff it carries no internal rows, is not the
     *  superadmin cross-domain superset, and targets the canonical DEFAULT domain. */
    private static boolean isPublicSafeDefaultRender(boolean canSeeInternal, boolean superadmin, String domain) {
        return !canSeeInternal
                && !superadmin
                && PrincipalDomain.forDomain("default").domain().equals(domain);
    }

    /** Visibility/role cut: public to all; internal only to admin/internal callers. */
    static boolean isVisibleTo(FederationModule m, boolean canSeeInternal) {
        String v = m.getVisibility() == null ? "public" : m.getVisibility();
        if ("internal".equalsIgnoreCase(v)) {
            return canSeeInternal;
        }
        return true; // 'public' (or any other value) is visible to everyone
    }

    /**
     * The active-scope-override cut. A module is suppressed (dropped from the
     * manifest) if ANY active scope override matches it:
     *
     * <ul>
     *   <li>{@code scope=all}  — matches EVERY module (global kill).</li>
     *   <li>{@code scope=user} — matches when {@code module.owner_user_id} equals
     *       the override target (the killed owner's modules; system NULL-owner
     *       modules are untouched).</li>
     *   <li>{@code scope=role} — matches when the module's declared
     *       {@code metadata.requiresRole} (case-insensitive) equals the override
     *       target role (see class javadoc for the honest limitation).</li>
     * </ul>
     *
     * <p>The {@code action} verb (circuit-break / unpublish / remove) is
     * informational here: an ACTIVE scope row drops the matched module from the
     * manifest while in effect, regardless of verb. Per-module-slug overrides are
     * NOT in this set (they already mutated the module at apply time and are
     * dropped by the DB finder), so there is no regression.
     */
    static boolean isSuppressedByScope(FederationModule m, List<FederationOverride> active) {
        for (FederationOverride o : active) {
            if (matches(m, o)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matches(FederationModule m, FederationOverride o) {
        // Route the closed all|user|role vocabulary through the ScopeKind enum. The
        // stored value is the SAME lowercase string; fromWire is a null-tolerant lens
        // (an unknown/null scope -> null -> "matches nothing", exactly the prior
        // string-equals fall-through). No DB/JSON value changes.
        ScopeKind kind = ScopeKind.fromWire(o.getScope());
        if (kind == null) {
            return false;
        }
        return switch (kind) {
            // scope=all matches EVERY module (global kill — the override's target is NULL).
            case ALL -> true;
            // scope=user matches when the module's owner equals the override target.
            case USER -> m.getOwnerUserId() != null && m.getOwnerUserId().equals(o.getTarget());
            // scope=role matches when the module's declared requiresRole equals the target (case-insensitive).
            case ROLE -> {
                String required = requiresRole(m.getMetadata());
                yield required != null && o.getTarget() != null
                        && required.equalsIgnoreCase(o.getTarget());
            }
        };
    }

    /**
     * Null-safe parse of the module's declared required role from its
     * {@code metadata} JSON ({@code {"requiresRole":"admin"}}). Pure CPU; no
     * blocking I/O, so it is safe on the reactive path. Returns {@code null} when
     * metadata is absent / unparseable / has no {@code requiresRole}.
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

    /** All enabled+closed rows as entities (used by tests + admin tooling). */
    public Flux<FederationModule> activeModules() {
        return repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed");
    }
}
