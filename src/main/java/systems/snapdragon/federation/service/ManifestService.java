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
import systems.snapdragon.federation.repository.FederationModuleRepository;
import systems.snapdragon.federation.repository.FederationOverrideRepository;
import systems.snapdragon.federation.security.DomainScope;
import systems.snapdragon.federation.security.Roles;

import java.time.Instant;
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

    /** The scope kinds that are applied at render time (not via per-module mutation). */
    private static final List<String> SCOPE_KINDS = List.of("all", "user", "role");

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
        DomainScope scope = (authorities != null && Roles.isSuperadmin(authorities))
                ? DomainScope.superadmin()
                : DomainScope.of("default");
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
     *   <li><b>SUPERADMIN</b> ({@code scope.isSuperadmin()}) — the un-pinned finders
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
    public Mono<FederationManifestDto> render(Set<String> authorities, DomainScope scope) {
        boolean canSeeInternal = authorities != null
                && (authorities.contains("ROLE_ADMIN") || authorities.contains("ROLE_INTERNAL")
                    || Roles.isSuperadmin(authorities));
        boolean superadmin = scope != null && scope.isSuperadmin();
        String domain = scope == null ? DomainScope.of("default").domain() : scope.domain();

        // Active scope-override set + module stream — pinned to the caller's domain
        // unless SUPERADMIN (un-pinned, all brands). Loaded ONCE per render.
        Flux<FederationOverride> activeScope = superadmin
                ? overrides.findByScopeInAndClearedAtIsNull(SCOPE_KINDS)
                : overrides.findByScopeInAndClearedAtIsNullAndDomain(SCOPE_KINDS, domain);
        Flux<FederationModule> modules = superadmin
                ? repo.findAllByEnabledTrueAndCircuitStateOrderByKindAscSlugAsc("closed")
                : repo.findAllByEnabledTrueAndCircuitStateAndDomainOrderByKindAscSlugAsc("closed", domain);

        return activeScope
                .collectList()
                .flatMap(active -> modules
                        .filter(m -> isVisibleTo(m, canSeeInternal))
                        .filter(m -> !isSuppressedByScope(m, active)) // active scope cut
                        .map(FederationRemoteDto::from)
                        .collectList()
                        .map(remotes -> new FederationManifestDto(Instant.now().toString(), remotes))
                        .flatMap(manifest -> {
                            // Write-through ONLY the public-safe DEFAULT-domain view
                            // (no internal rows, no superadmin cross-domain superset)
                            // so a cache poller without a token never sees internal
                            // remotes NOR another brand's remotes. Best-effort; failure
                            // swallowed in the cache. (A per-brand cache key is a later
                            // enhancement — until then only the canonical default
                            // public view is cached, never a brand-specific or
                            // cross-domain one.)
                            if (!canSeeInternal && !superadmin
                                    && DomainScope.of("default").domain().equals(domain)) {
                                return cache.put(manifest).thenReturn(manifest);
                            }
                            return Mono.just(manifest);
                        }));
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
        String scope = o.getScope();
        if ("all".equals(scope)) {
            return true;
        }
        if ("user".equals(scope)) {
            return m.getOwnerUserId() != null && m.getOwnerUserId().equals(o.getTarget());
        }
        if ("role".equals(scope)) {
            String required = requiresRole(m.getMetadata());
            return required != null && o.getTarget() != null
                    && required.equalsIgnoreCase(o.getTarget());
        }
        return false;
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
