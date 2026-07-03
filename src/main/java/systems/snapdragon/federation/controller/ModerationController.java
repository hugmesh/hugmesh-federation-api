package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.service.ModerationService;
import systems.snapdragon.federation.web.ValidationPatterns;

/**
 * The moderation workflow surface — recommend / refer / decide.
 *
 * <p>Mirrors the games {@code ModerationController}'s three-step workflow:
 * <ol>
 *   <li><b>Submit</b> ({@code POST /}) — a mod opens a moderation request
 *       (status {@code recommended}).</li>
 *   <li><b>Refer</b> ({@code POST /{id}/refer}) — a mod escalates the request
 *       to admins (status {@code referred}).</li>
 *   <li><b>Decide</b> ({@code POST /{id}/decide}) — an admin approves or denies
 *       (status {@code approved} / {@code denied}).</li>
 * </ol>
 *
 * <p>An {@code approved} {@code user-removal} decision is AUTO-APPLIED by
 * {@link ModerationService#decide} as an active scope=user kill-switch override
 * (tagged {@code moderation_request:<id>}); a {@code denied} re-decision rearms
 * only that request's own row(s). The decision row and the override row are
 * recorded separately so both legs stay independently auditable. An
 * {@code approved} {@code instance-block} remains decision-only (no
 * remote-instance surface exists in this catalogue; nothing is faked).
 *
 * <h2>Security gating</h2>
 * <p>All paths under {@code /api/federation/moderation/**} require
 * {@code ROLE_MOD}, {@code ROLE_ADMIN}, or {@code ROLE_SUPERADMIN} at the
 * path level (see {@link systems.snapdragon.federation.config.SecurityConfig}).
 * Method-security ({@code @PreAuthorize}) further narrows the decide endpoint to
 * {@code ROLE_ADMIN} or {@code ROLE_SUPERADMIN}. This is defence-in-depth: both
 * gates must be passed.
 *
 * <p><b>Exception — {@code POST /recommend-instance-block}</b>: this ONE sub-path is
 * a narrower, self-service surface for a plain platform participant ({@code
 * ROLE_MATRIX} or {@code ROLE_MASTODON}) — NOT a mod/admin — to FILE an
 * instance-block recommendation (the chain's first hop: USER files -> MOD refers ->
 * ADMIN decides). It is a distinct, more specific path/method rule (and a distinct
 * {@code @PreAuthorize}) from the {@code hasAnyRole('MOD','ADMIN','SUPERADMIN')}
 * gate that governs {@code submit}/{@code list}/{@code refer}/{@code decide} above.
 * {@code kind} is HARDCODED server-side to {@code instance-block} on that path
 * (never caller-supplied), so a platform-only caller can never use it to file a
 * {@code user-removal} request, and it grants no list/refer/decide capability. See
 * {@link #recommendInstanceBlock} and
 * {@link systems.snapdragon.federation.config.SecurityConfig} for the full
 * root-cause writeup: {@code snapdragon-user-bff-api}'s {@code POST
 * /bff/user/recommend-instance-block} used to forward a plain user's own JWT
 * straight into the mod-only {@code submit} surface, which no role hierarchy could
 * ever admit — so the feature was end-to-end unreachable until this dedicated
 * endpoint was added.
 *
 * <h2>Domain scoping</h2>
 * <p>Every operation is DOMAIN-scoped from the validated JWT issuer via
 * {@link PrincipalDomain#resolve}. A per-domain mod/admin sees and acts ONLY on
 * their own brand's requests; a cross-domain request ID returns 404. SUPERADMIN
 * has a cross-brand (all-domains) view.
 *
 * @see ModerationService
 * @see systems.snapdragon.federation.config.SecurityConfig
 */
@Tag(name = "Moderation",
        description = "Recommend / refer / decide moderation workflow. "
                + "ROLE_MOD submits + refers; ROLE_ADMIN decides. DOMAIN-scoped.")
@RestController
@RequestMapping("/api/federation/moderation")
@Validated
public class ModerationController {

    private final ModerationService moderation;
    private final DomainRegistry domains;

    public ModerationController(ModerationService moderation, DomainRegistry domains) {
        this.moderation = moderation;
        this.domains = domains;
    }

    // -------------------------------------------------------------------------
    // Request body records
    // -------------------------------------------------------------------------

    /**
     * Body for {@code POST /} (submit a moderation request). Both {@code kind} and
     * {@code target} are required — {@code kind} is validated against the
     * {@code moderation_requests.kind} CHECK vocabulary (mirrors
     * {@link ModerationService#submit}), and {@code target} is a NOT-NULL column, so
     * both are validated here for a clean 400 before the DB.
     *
     * @param kind   moderation kind — one of {@code instance-block} or {@code user-removal}
     * @param target the instance host or user ID the action is aimed at (max 1 024 chars)
     * @param reason optional human-readable context (max 1 024 chars)
     */
    public record SubmitRequest(
            @NotBlank(message = "kind is required")
            @Pattern(regexp = ValidationPatterns.MODERATION_KIND,
                    message = "kind must be instance-block|user-removal") String kind,
            @NotBlank(message = "target is required")
            @Size(max = 1024, message = "target must be at most 1024 chars") String target,
            @Size(max = 1024, message = "reason must be at most 1024 chars") String reason) {}

    /**
     * Body for {@code POST /recommend-instance-block} (self-service platform-user
     * recommendation). Deliberately has NO {@code kind} field — unlike
     * {@link SubmitRequest} — because the kind is HARDCODED server-side to
     * {@code instance-block} in {@link #recommendInstanceBlock}, so a plain
     * platform-only caller can never use this narrower surface to file a
     * {@code user-removal} request.
     *
     * @param target the homeserver/instance domain being recommended for a block
     *               (max 1 024 chars)
     * @param reason optional free-text context (max 1 024 chars)
     */
    public record RecommendInstanceBlockRequest(
            @NotBlank(message = "target is required")
            @Size(max = 1024, message = "target must be at most 1024 chars") String target,
            @Size(max = 1024, message = "reason must be at most 1024 chars") String reason) {}

    // -------------------------------------------------------------------------
    // List
    // -------------------------------------------------------------------------

    @Operation(
        summary = "List moderation requests in the caller's domain (SUPERADMIN: all domains).",
        description = """
            Returns all moderation requests visible to the caller, ordered newest-first.
            An optional <code>status</code> parameter narrows the results.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Rows visible</th></tr>
              <tr><td>ROLE_MOD</td>
                  <td>Own brand's requests (all statuses)</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Own brand's requests (all statuses); may filter by status</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>All brands' requests (cross-domain control-plane view)</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "List returned — empty array when no requests match the caller's "
                + "domain (and optional status filter)."),
        @ApiResponse(responseCode = "400",
            description = "status parameter is not one of recommended|referred|approved|denied."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying moderation_requests. Check server logs.")
    })
    @GetMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Flux<ModerationRequest> list(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false)
            @Pattern(regexp = ValidationPatterns.MODERATION_STATUS,
                    message = "status must be recommended|referred|approved|denied") String status) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        // Route to the status-filtered or full-list finder based on whether the
        // caller supplied a status filter.
        return status == null ? moderation.list(scope) : moderation.listByStatus(status, scope);
    }

    // -------------------------------------------------------------------------
    // Submit
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Submit a moderation request (mod recommends).",
        description = """
            Opens a new moderation request stamped with status <code>recommended</code>
            and the caller's domain. The <code>requester</code> is the mod's Casdoor
            subject (from the JWT).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_MOD / ROLE_ADMIN / ROLE_SUPERADMIN</td>
                  <td>Request created in caller's domain; SUPERADMIN lands in
                      <code>"default"</code></td></tr>
            </table>

            <p>The domain is stamped from the authenticated JWT — never from the
            request body — so a request is always attributed to the correct brand.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Moderation request created and returned with status=recommended."),
        @ApiResponse(responseCode = "400",
            description = "kind is not instance-block|user-removal, or target / reason exceed "
                + "their maximum length."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while saving the request. Check server logs.")
    })
    @PostMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Mono<ModerationRequest> submit(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody SubmitRequest req) {
        // The requester identity comes from the validated JWT subject, not from the
        // request body, so it cannot be spoofed.
        return moderation.submit(jwt.getSubject(), req.kind(), req.target(), req.reason(),
                PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Recommend (self-service, platform-user only) — the chain's FIRST hop
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Self-service: recommend an instance block (USER->MOD->ADMIN chain start). "
                + "Requires a platform role, NOT mod/admin.",
        description = """
            Opens a new moderation request stamped <code>kind=instance-block</code>,
            <code>status=recommended</code>, in the caller's domain. UNLIKE
            <code>POST /</code> (the mod/admin submit surface above), this narrower
            endpoint accepts a plain platform participant &mdash; <code>ROLE_MATRIX</code>
            or <code>ROLE_MASTODON</code> &mdash; and REJECTS a mod/admin/superadmin that
            holds neither platform role. <code>kind</code> is HARDCODED server-side
            (there is no <code>kind</code> field on the request body), so this surface
            can never be used to file a <code>user-removal</code> request, and it grants
            no list/refer/decide capability &mdash; only "file one recommendation".

            <p>This is the transport <code>snapdragon-user-bff-api</code>'s
            <code>POST /bff/user/recommend-instance-block</code> forwards to (the
            caller's own bearer, unmodified).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_MATRIX / ROLE_MASTODON</td>
                  <td>Request created in caller's domain, kind=instance-block,
                      status=recommended</td></tr>
              <tr><td>ROLE_MOD / ROLE_ADMIN / ROLE_SUPERADMIN (no platform role)</td>
                  <td>403 &mdash; this surface is for platform participants; staff use
                      <code>POST /</code> instead</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Moderation request created and returned with status=recommended, "
                + "kind=instance-block."),
        @ApiResponse(responseCode = "400",
            description = "Missing target, or target / reason exceed their maximum length."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_MATRIX or ROLE_MASTODON."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while saving the request. Check server logs.")
    })
    @PostMapping("/recommend-instance-block")
    @PreAuthorize("hasAnyRole('MATRIX','MASTODON')")
    public Mono<ModerationRequest> recommendInstanceBlock(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody RecommendInstanceBlockRequest req) {
        // kind is HARDCODED to instance-block — NEVER taken from the caller — so a
        // platform-only principal can never file a user-removal request through this
        // narrower self-service surface. requester is the caller's own JWT subject
        // (a plain user here, not a mod) — ModerationService.submit is role-agnostic
        // about who the requester is; the role gate lives entirely at the API
        // boundary (path rule + this @PreAuthorize).
        return moderation.submit(jwt.getSubject(), "instance-block", req.target(), req.reason(),
                PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Refer
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Refer a request up to admins (mod escalates).",
        description = """
            Escalates a <code>recommended</code> request to <code>referred</code>
            status, stamping the caller (mod) as <code>modReferrer</code>. The
            request is loaded domain-pinned to the caller's brand, so a per-domain
            mod can NEVER refer another brand's request (cross-domain ID → 404).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_MOD / ROLE_ADMIN</td>
                  <td>Refer own brand's request; cross-domain ID → 404</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Refer any request across all brands</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Moderation request updated and returned with status=referred."),
        @ApiResponse(responseCode = "400",
            description = "id path variable is not a positive number."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No moderation request with that ID visible to the caller's domain."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while updating the request. Check server logs.")
    })
    @PostMapping("/{id}/refer")
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Mono<ModerationRequest> refer(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Positive(message = "id must be a positive number") Long id) {
        // The domain predicate in the service load ensures cross-domain IDs 404.
        return moderation.refer(id, jwt.getSubject(), PrincipalDomain.resolve(jwt, domains));
    }

    // -------------------------------------------------------------------------
    // Decide
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Decide a request (admin approves / denies).",
        description = """
            Sets the request status to <code>approved</code> or <code>denied</code>
            based on the <code>approve</code> query parameter, and stamps the caller
            (admin) as <code>adminDecider</code>. The request is loaded domain-pinned,
            so a per-domain admin can NEVER decide another brand's request
            (cross-domain ID → 404).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_MOD</td>
                  <td>403 — mods may submit + refer but not decide</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Decide own brand's request; cross-domain ID → 404</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Decide any request across all brands</td></tr>
            </table>

            <p>An <code>approved</code> <b>user-removal</b> decision is auto-applied
            as an active scope=user kill-switch override (action
            <code>unpublish</code>, tagged <code>moderation_request:&lt;id&gt;</code>):
            the target's modules drop from the manifest render and their vanity
            profile is suppressed. A <code>denied</code> re-decision rearms only the
            row(s) this request applied. The decision row and the override row are
            recorded separately for auditability. An <code>approved</code>
            <b>instance-block</b> remains decision-only — the federation catalogue
            has no remote-instance surface; the approved row authorises the
            homeserver-level block executed elsewhere.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Moderation request updated and returned with status=approved or denied."),
        @ApiResponse(responseCode = "400",
            description = "id path variable is not a positive number, or approve parameter is missing."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "404",
            description = "No moderation request with that ID visible to the caller's domain."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while updating the request. Check server logs.")
    })
    @PostMapping("/{id}/decide")
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    public Mono<ModerationRequest> decide(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Positive(message = "id must be a positive number") Long id,
            @RequestParam boolean approve) {
        // approve=true → "approved", false → "denied" (translated in the service).
        return moderation.decide(id, approve, jwt.getSubject(), PrincipalDomain.resolve(jwt, domains));
    }
}
