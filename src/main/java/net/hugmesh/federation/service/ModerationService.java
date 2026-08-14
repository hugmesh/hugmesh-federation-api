package net.hugmesh.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.model.ModerationRequest;
import net.hugmesh.federation.repository.ModerationRequestRepository;
import net.hugmesh.commons.security.PrincipalDomain;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Three-step recommend / refer / decide moderation workflow for the
 * {@code moderation_requests} table.
 *
 * <h2>Responsibility</h2>
 *
 * <p>This service implements the platform-level moderation workflow that governs
 * federation actions such as blocking a remote instance or removing a federated
 * user.  It is separate from the admin kill-switch surface ({@link OverrideService})
 * and from day-to-day content moderation that mods perform on individual posts: its
 * purpose is to provide a structured, multi-role approval trail before a
 * consequential federation action is authorised.
 *
 * <p>Every request moves through a fixed lifecycle:
 *
 * <ol>
 *   <li>{@link #submit} — a mod (or admin, or superadmin) opens a request via
 *       {@code POST /}; OR a plain platform participant (ROLE_MATRIX/MASTODON)
 *       files an instance-block recommendation via the narrower, self-service
 *       {@code POST /recommend-instance-block} (kind hardcoded there); either way
 *       the row lands with {@code status = recommended}.</li>
 *   <li>{@link #refer}  — a mod escalates it to admins; {@code status} advances to
 *       {@code referred}.</li>
 *   <li>{@link #decide} — an admin (or superadmin) closes it with either
 *       {@code approved} or {@code denied}.</li>
 * </ol>
 *
 * <p>An {@code approved} {@code user-removal} decision is AUTO-APPLIED as a
 * scope=user {@link net.hugmesh.federation.model.FederationOverride} via
 * {@link OverrideService#applyUserScope(String, String, String, String, PrincipalDomain)},
 * tagged {@code reason='moderation_request:<id>'} so the two steps remain
 * independently auditable (the decision row AND the override row) and so a
 * subsequent {@code denied} re-decision rearms ONLY the row(s) this request
 * applied (via {@link OverrideService#clearScopeBySource(String, PrincipalDomain)}).
 * An {@code approved} {@code instance-block} stays decision-only: the federation
 * catalogue has no remote-instance surface, so there is nothing here to apply the
 * block TO — the approved row is the auditable authorisation signal for the
 * homeserver-level block executed by the mod/admin surfaces (never faked here).
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <p>All access is domain-scoped: a per-domain principal can only see and act on
 * requests belonging to their own brand.  ROLE_SUPERADMIN is the sole exception
 * and operates across all brands without a domain predicate.
 *
 * <pre>
 *  Role                  │ list        │ submit      │ refer       │ decide
 *  ──────────────────────┼─────────────┼─────────────┼─────────────┼──────────────
 *  ROLE_MOD              │ own domain  │ own domain  │ own domain  │ —
 *  ROLE_ADMIN            │ own domain  │ own domain  │ own domain  │ own domain
 *  ROLE_SUPERADMIN       │ ALL domains │ ALL domains │ ALL domains │ ALL domains
 *  ROLE_MATRIX/MASTODON  │ —           │ own domain* │ —           │ —
 * </pre>
 * <p>* ROLE_MATRIX/MASTODON's "submit" is NOT the {@code POST /} surface above — it
 * is the separate, narrower {@code POST /recommend-instance-block} self-service
 * path, {@code kind=instance-block} ONLY (server-hardcoded, never caller-chosen).
 *
 * @see net.hugmesh.federation.controller.ModerationController
 * @see ModerationRequestRepository
 * @see ModerationRequest
 * @see OverrideService
 * @see PrincipalDomain
 */
@Service
public class ModerationService {

    /**
     * Prefix of the SOURCE tag stamped on the {@code federation_override} row an
     * approved {@code user-removal} decision applies ({@code reason} column):
     * {@code moderation_request:<id>}. The tag is what keeps the auto-application
     * auditable AND reversible per-request — a later {@code denied} re-decision
     * clears ONLY rows carrying this request's own tag, never a manual kill or
     * another request's row (mirrors the access-suspension
     * {@code 'access_suspension:<id>'} convention).
     */
    static final String DECISION_SOURCE_PREFIX = "moderation_request:";

    private final ModerationRequestRepository repo;
    private final OverrideService overrides;

    public ModerationService(ModerationRequestRepository repo, OverrideService overrides) {
        this.repo = repo;
        this.overrides = overrides;
    }

    // ----- Listing -----

    /**
     * Returns all moderation requests in scope, ordered by timestamp descending
     * (most recent first).
     *
     * <p>A per-domain principal (ROLE_MOD, ROLE_ADMIN) sees ONLY requests that
     * belong to their own brand.  ROLE_SUPERADMIN sees every request across all
     * brands.  The domain cut is enforced in the DB query, not in application code.
     *
     * @param scope the caller's resolved tenant scope; {@code scope.superadmin()}
     *              selects the un-pinned all-brands finder
     * @return a {@code Flux} streaming {@link ModerationRequest} rows ordered by
     *         {@code ts} descending; empty when no requests exist in scope
     * @see ModerationRequestRepository#findAllByOrderByTsDesc()
     * @see ModerationRequestRepository#findByDomainOrderByTsDesc(String)
     */
    public Flux<ModerationRequest> list(PrincipalDomain scope) {
        return scope.superadmin()
                ? repo.findAllByOrderByTsDesc()
                : repo.findByDomainOrderByTsDesc(scope.domain());
    }

    /**
     * Returns all moderation requests in scope that carry the given status, ordered
     * by timestamp descending.
     *
     * <p>The domain cut follows the same SUPERADMIN / per-domain logic as
     * {@link #list(PrincipalDomain)}.
     *
     * @param status the workflow status to filter on; one of
     *               {@code recommended | referred | approved | denied}
     * @param scope  the caller's resolved tenant scope
     * @return a {@code Flux} streaming matching {@link ModerationRequest} rows
     *         ordered by {@code ts} descending; empty when none match
     * @see ModerationRequestRepository#findByStatusOrderByTsDesc(String)
     * @see ModerationRequestRepository#findByStatusAndDomainOrderByTsDesc(String, String)
     */
    public Flux<ModerationRequest> listByStatus(String status, PrincipalDomain scope) {
        return scope.superadmin()
                ? repo.findByStatusOrderByTsDesc(status)
                : repo.findByStatusAndDomainOrderByTsDesc(status, scope.domain());
    }

    // ----- Workflow Mutations -----

    /**
     * Opens a new moderation request in the caller's domain with
     * {@code status = recommended}.
     *
     * <p>ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN may submit via {@code POST /}; a
     * plain platform participant (ROLE_MATRIX/ROLE_MASTODON) may ALSO reach this
     * method via the narrower {@code POST /recommend-instance-block} self-service
     * surface (kind hardcoded to {@code instance-block} there — see
     * {@link net.hugmesh.federation.controller.ModerationController#recommendInstanceBlock}).
     * This method itself is role-agnostic; the caller-class gate lives entirely at
     * the two API boundaries. The {@code domain} column is stamped from the
     * caller's authenticated scope — never from the request body — so the row is
     * visible only to staff of the same brand.  A ROLE_SUPERADMIN submit (no brand
     * in scope) lands in {@code "default"}.
     *
     * @param requester the submitting principal's Casdoor subject (a mod/admin via
     *                  {@code POST /}, or a plain platform participant via
     *                  {@code POST /recommend-instance-block}), recorded as the
     *                  originator of the request
     * @param kind      the requested action vocabulary; must be
     *                  {@code instance-block} or {@code user-removal}
     * @param target    the instance hostname (for {@code instance-block}) or the
     *                  federated user identifier (for {@code user-removal})
     * @param reason    a human-readable justification; may be {@code null}
     * @param scope     the caller's resolved tenant scope, used to stamp
     *                  {@code domain} on the new row
     * @return a {@code Mono} emitting the saved {@link ModerationRequest} with
     *         {@code status = recommended} and {@code ts} set to the current instant
     * @throws ResponseStatusException with status {@code 400 BAD_REQUEST} when
     *                                 {@code kind} is not a recognised vocabulary
     *                                 value
     * @see #refer(Long, String, PrincipalDomain)
     * @see #decide(Long, boolean, String, PrincipalDomain)
     */
    public Mono<ModerationRequest> submit(String requester, String kind, String target, String reason,
                                          PrincipalDomain scope) {
        if (!isKind(kind)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST,
                    "kind must be instance-block | user-removal"));
        }
        ModerationRequest r = new ModerationRequest();
        r.setRequester(requester);
        r.setKind(kind);
        r.setTarget(target);
        r.setReason(reason);
        r.setStatus("recommended");
        r.setDomain(domainForWrite(scope));
        r.setTs(Instant.now());
        return repo.save(r);
    }

    /**
     * Escalates a {@code recommended} request to admins by advancing its status to
     * {@code referred}.
     *
     * <p>ROLE_MOD (or ROLE_ADMIN, or ROLE_SUPERADMIN) may refer.  The request is
     * loaded pinned to the caller's domain so a per-domain mod can never refer
     * another brand's request — a cross-domain id resolves to empty and surfaces
     * as a 404.  ROLE_SUPERADMIN may refer any request regardless of domain.
     *
     * @param id          the primary-key id of the request to escalate
     * @param modReferrer the referring mod's (or admin's) Casdoor subject, recorded
     *                    on the row as {@code mod_referrer}
     * @param scope       the caller's resolved tenant scope, used to pin the load
     *                    to the correct brand
     * @return a {@code Mono} emitting the updated {@link ModerationRequest} with
     *         {@code status = referred} and {@code ts} refreshed to the current instant
     * @throws ResponseStatusException with status {@code 404 NOT_FOUND} when no
     *                                 request with the given id exists in scope, or
     *                                 when it belongs to another brand
     * @see #decide(Long, boolean, String, PrincipalDomain)
     */
    public Mono<ModerationRequest> refer(Long id, String modReferrer, PrincipalDomain scope) {
        return load(id, scope)
                .flatMap(r -> {
                    r.setStatus("referred");
                    r.setModReferrer(modReferrer);
                    r.setTs(Instant.now());
                    return repo.save(r);
                });
    }

    /**
     * Closes a moderation request with an admin decision: approved or denied.
     *
     * <p>ROLE_ADMIN or ROLE_SUPERADMIN may decide.  The request is loaded pinned to
     * the caller's domain so a per-domain admin can never decide another brand's
     * request — a cross-domain id resolves to empty and surfaces as a 404.
     * ROLE_SUPERADMIN may decide any request regardless of domain.
     *
     * <p><b>Decision application (the decide→apply chain).</b> An {@code approved}
     * {@code user-removal} decision is auto-applied as an ACTIVE scope=user
     * {@code federation_override} row via
     * {@link OverrideService#applyUserScope(String, String, String, String, PrincipalDomain)}
     * (action {@code unpublish}: the owner's modules drop from the manifest render
     * and their vanity profile is suppressed — matching the access-suspension ban
     * path).  The override row is stamped with the DECIDED REQUEST's own domain
     * (not the decider's — relevant for a SUPERADMIN deciding a brand row) and
     * tagged {@code reason='moderation_request:<id>'}, so the decision row and the
     * override row each appear in the audit trail independently.  A {@code denied}
     * decision of a {@code user-removal} clears (rearms) any active override row(s)
     * previously applied by THIS request's tag — count zero for a first-time deny —
     * so flipping a mistaken approve restores the target without touching manual
     * kills.  An {@code approved} {@code instance-block} stays decision-only (no
     * remote-instance surface exists in this catalogue; nothing is faked).
     *
     * <p>The returned {@code Mono} completes ONLY after both the decision row and
     * the override application (when one is due) have landed; an override-store
     * failure surfaces as the call's error — the decide NEVER reports success on a
     * half-applied chain.  (The decision row may already be persisted in that
     * failure case; re-issuing the decide is safe: it re-saves the same status and
     * re-applies the override idempotently by source tag.)
     *
     * @param id           the primary-key id of the request to decide
     * @param approve      {@code true} to advance status to {@code approved};
     *                     {@code false} to advance to {@code denied}
     * @param adminDecider the deciding admin's (or superadmin's) Casdoor subject,
     *                     recorded on the row as {@code admin_decider}
     * @param scope        the caller's resolved tenant scope, used to pin the load
     *                     to the correct brand
     * @return a {@code Mono} emitting the updated {@link ModerationRequest} with
     *         {@code status = approved | denied} and {@code ts} refreshed to the
     *         current instant, after any due override application/clear completed
     * @throws ResponseStatusException with status {@code 404 NOT_FOUND} when no
     *                                 request with the given id exists in scope, or
     *                                 when it belongs to another brand
     * @see OverrideService#applyUserScope(String, String, String, String, PrincipalDomain)
     * @see OverrideService#clearScopeBySource(String, PrincipalDomain)
     */
    public Mono<ModerationRequest> decide(Long id, boolean approve, String adminDecider, PrincipalDomain scope) {
        return load(id, scope)
                .flatMap(r -> {
                    r.setStatus(approve ? "approved" : "denied");
                    r.setAdminDecider(adminDecider);
                    r.setTs(Instant.now());
                    return repo.save(r);
                })
                .flatMap(saved -> applyDecision(saved, approve, adminDecider));
    }

    /**
     * Applies the side-effect of a decision to the kill-switch surface (the
     * decide→apply chain).  Only {@code user-removal} requests have an applicable
     * federation surface (the owner's modules + vanity profile, keyed on
     * {@code owner_user_id = target}):
     *
     * <ul>
     *   <li>{@code approved} — write the ACTIVE scope=user override row (action
     *       {@code unpublish}) tagged with this request's source.</li>
     *   <li>{@code denied} — clear any active row(s) carrying this request's source
     *       tag (rearm after a flipped approve; zero rows on a first-time deny).</li>
     * </ul>
     *
     * <p>{@code instance-block} (and any row with no kind, defensively) passes
     * through untouched — decision-only, honestly.  The override lands in the
     * REQUEST row's own domain so a SUPERADMIN decision of a brand-X request
     * suppresses brand-X's render, not a phantom {@code "default"}.
     *
     * @param saved        the just-saved decision row
     * @param approve      the decision that was applied to the row
     * @param adminDecider the deciding admin's Casdoor subject (stamped as the
     *                     override row's {@code set_by})
     * @return a {@code Mono} emitting {@code saved} after the side-effect completes
     */
    private Mono<ModerationRequest> applyDecision(ModerationRequest saved, boolean approve, String adminDecider) {
        if (!"user-removal".equals(saved.getKind())) {
            return Mono.just(saved);
        }
        String source = DECISION_SOURCE_PREFIX + saved.getId();
        // The override is scoped to the DECIDED ROW's brand (the load already proved
        // the caller may act on it); a NULL domain (pre-026 data) lands in "default".
        PrincipalDomain rowScope = PrincipalDomain.forDomain(
                saved.getDomain() == null ? "default" : saved.getDomain());
        Mono<?> effect = approve
                ? overrides.applyUserScope(saved.getTarget(), "unpublish", adminDecider, source, rowScope)
                : overrides.clearScopeBySource(source, rowScope);
        return effect.thenReturn(saved);
    }

    // ----- Helpers -----

    /**
     * Loads a moderation request by id, pinned to the caller's domain.
     *
     * <p>A per-domain principal uses the domain-scoped finder so a request that
     * belongs to another brand resolves to empty — indistinguishable from absent,
     * and always surfaced as a 404.  ROLE_SUPERADMIN uses the un-pinned
     * {@code findById} with no domain predicate.
     *
     * @param id    the primary-key id of the request to load
     * @param scope the caller's resolved tenant scope; {@code scope.superadmin()}
     *              selects the un-pinned finder
     * @return a {@code Mono} emitting the matching {@link ModerationRequest}
     * @throws ResponseStatusException with status {@code 404 NOT_FOUND} when the
     *                                 request does not exist in scope or belongs to
     *                                 another brand
     */
    private Mono<ModerationRequest> load(Long id, PrincipalDomain scope) {
        Mono<ModerationRequest> found = scope.superadmin()
                ? repo.findById(id)
                : repo.findByIdAndDomain(id, scope.domain());
        return found.switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no request: " + id)));
    }

    /**
     * Resolves the domain to stamp on a written request row.
     *
     * <p>For a per-domain principal the value is taken from the authenticated scope
     * (never from the request body).  For a ROLE_SUPERADMIN submit (no brand in
     * scope) the row lands in {@code "default"}.
     *
     * @param scope the caller's resolved tenant scope
     * @return the domain string to write into the {@code domain} column
     */
    private static String domainForWrite(PrincipalDomain scope) {
        return scope.superadmin() ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    /**
     * Returns {@code true} iff {@code k} is a recognised {@code kind} vocabulary
     * value: {@code instance-block} or {@code user-removal}.
     *
     * @param k the kind string to validate
     * @return {@code true} for the two recognised kinds; {@code false} otherwise
     */
    private static boolean isKind(String k) {
        return "instance-block".equals(k) || "user-removal".equals(k);
    }
}
