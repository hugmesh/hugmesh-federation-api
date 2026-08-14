package net.hugmesh.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.model.UsernameAvailabilityDto;
import net.hugmesh.federation.service.UsernameAvailabilityService;
import net.hugmesh.federation.web.ValidationPatterns;

/**
 * Username availability / confusable CHECK — the registry-owned look-alike gate.
 *
 * <p>Every endpoint here is an ENUMERATION ORACLE: the {@code matchedWith} field in
 * the response names the colliding username or reserved label. The whole controller is
 * therefore gated to internal service credentials ({@code ROLE_SERVICE}) and admin
 * roles — it is NEVER on the public / SPA surface.
 *
 * <h2>Endpoints</h2>
 * <ul>
 *   <li>{@code GET /{candidate}/availability} — the primary registration gate.
 *       The mint paths (Casdoor pre-signup webhook, OAuth provider-handle mint,
 *       actions / user-bff / admin-bff) call this before granting a username.
 *       Supports an optional {@code override=confusable} query parameter.</li>
 *   <li>{@code POST /check} — same check by request body for callers that prefer
 *       a POST (same semantics, same override support).</li>
 *   <li>{@code GET /{candidate}/confusables} — ADMIN debug: returns the computed
 *       skeleton and any reserved match WITHOUT a full DB collision scan, for
 *       tuning the skeleton / reserved-label configuration.</li>
 * </ul>
 *
 * <h2>Security gating</h2>
 * <p>{@code /api/federation/username/**} is gated to {@code ROLE_SERVICE},
 * {@code ROLE_ADMIN}, or {@code ROLE_SUPERADMIN} at the path level (see
 * {@link net.hugmesh.federation.config.SecurityConfig}) AND by the
 * class-level {@code @PreAuthorize}. This is defence-in-depth.
 *
 * <h2>Override behaviour</h2>
 * <p>{@code override=confusable} (ROLE_ADMIN only, audited here) flips a
 * {@code reason=confusable} or {@code reason=exact} verdict to {@code available}.
 * It NEVER overrides a {@code reason=reserved} or a hard reject
 * ({@code mixed-script} / {@code zero-width} / {@code empty}). Non-admins who
 * supply the override parameter receive the unmodified verdict silently — the
 * override request is never surfaced as an error to avoid leaking the override
 * capability.
 *
 * <h2>Self-exclusion</h2>
 * <p>The {@code self} parameter excludes the caller's OWN existing username by
 * EXACT username equality only — a different-but-confusable owner stays flagged.
 *
 * @see UsernameAvailabilityService
 * @see net.hugmesh.federation.config.SecurityConfig
 */
@Tag(name = "Username",
        description = "Username availability + confusable check. "
                + "INTERNAL / ROLE_SERVICE — not a public surface.")
@RestController
@RequestMapping("/api/federation/username")
@PreAuthorize("hasAnyRole('SERVICE', 'ADMIN')")
@Validated
public class UsernameAvailabilityController {

    /**
     * Structured AUDIT logger — the durable record of a {@code ROLE_ADMIN}
     * confusable-override event. Separate from the application logger so audit
     * lines can be routed to a separate log sink / SIEM by log appender config.
     * A confusable override is non-destructive (no domain row is mutated), but it
     * is irreversible at the call site, so every successful override is logged
     * with actor, candidate, skeleton, reason, and matchedWith fields.
     */
    private static final Logger AUDIT = LoggerFactory.getLogger("net.hugmesh.federation.AUDIT");

    private final UsernameAvailabilityService availability;

    public UsernameAvailabilityController(UsernameAvailabilityService availability) {
        this.availability = availability;
    }

    // -------------------------------------------------------------------------
    // GET /{candidate}/availability  (primary registration gate)
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Check whether a candidate username is available "
                + "(collision / reserved / confusable).",
        description = """
            Runs the three-tier availability check for a candidate username and returns
            a verdict:
            <ul>
              <li><b>available</b> — the username passes all tiers.</li>
              <li><b>collide / reason=exact</b> — an existing username has the same
                  confusable skeleton (homoglyph / leet collision).</li>
              <li><b>collide / reason=reserved</b> — the skeleton matches a reserved
                  label or its confusables (e.g. <code>4dmin</code>). NOT overridable.</li>
              <li><b>collide / reason=confusable</b> — an edit-distance typo-squat or
                  affix anti-impersonation match.</li>
              <li><b>collide / reason=mixed-script / zero-width / empty</b> — hard
                  reject. NOT overridable.</li>
            </ul>

            <h4>Parameters</h4>
            <ul>
              <li><code>self</code> — the caller's OWN existing username (exact
                  equality); excluded from the skeleton collision check so a username
                  holder can re-check their own handle without a false collision.</li>
              <li><code>override=confusable</code> — ROLE_ADMIN only; flips a
                  <code>reason=exact</code> or <code>reason=confusable</code> verdict
                  to available and writes an AUDIT log line. Non-admins receive the
                  unmodified verdict (no error).</li>
            </ul>

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Can use override=confusable?</th></tr>
              <tr><td>ROLE_SERVICE</td><td>No — override silently ignored</td></tr>
              <tr><td>ROLE_ADMIN / ROLE_SUPERADMIN</td>
                  <td>Yes — override applied + audited</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Verdict returned — available=true or available=false with reason "
                + "and matchedWith fields."),
        @ApiResponse(responseCode = "400",
            description = "candidate path variable fails the DNS-label-token pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_SERVICE, ROLE_ADMIN, or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error during the skeleton collision scan. Check server logs.")
    })
    @GetMapping("/{candidate}/availability")
    public Mono<UsernameAvailabilityDto> availability(
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String candidate,
            @RequestParam(value = "self", required = false) String self,
            @RequestParam(value = "override", required = false) String override,
            @AuthenticationPrincipal Jwt jwt) {
        return checkAndMaybeOverride(candidate, self, override, jwt);
    }

    // -------------------------------------------------------------------------
    // POST /check  (request-body form)
    // -------------------------------------------------------------------------

    /**
     * Request body for {@code POST /check}. All three fields mirror the query
     * parameters on the GET form; see {@link #availability} for semantics.
     *
     * @param candidate the username candidate to check (required)
     * @param self      the caller's own current username for self-exclusion (optional)
     * @param override  {@code "confusable"} to apply the admin override (optional)
     */
    public record CheckRequest(String candidate, String self, String override) {}

    @Operation(
        summary = "Check a candidate username by request body.",
        description = """
            Identical to <code>GET /{candidate}/availability</code> but accepts the
            candidate + self + override in a JSON request body. For callers that prefer
            POST or that carry long override / self values.
            See <code>GET /{candidate}/availability</code> for the full semantics.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Verdict returned — available=true or available=false with reason "
                + "and matchedWith fields."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_SERVICE, ROLE_ADMIN, or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error during the skeleton collision scan. Check server logs.")
    })
    @PostMapping("/check")
    public Mono<UsernameAvailabilityDto> check(
            @RequestBody CheckRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        return checkAndMaybeOverride(req.candidate(), req.self(), req.override(), jwt);
    }

    // -------------------------------------------------------------------------
    // GET /{candidate}/confusables  (ADMIN debug — no DB scan)
    // -------------------------------------------------------------------------

    @Operation(
        summary = "ADMIN debug: return the computed skeleton and any reserved match "
                + "for a candidate (no DB collision scan).",
        description = """
            Returns the confusable skeleton for a candidate username and any
            reserved-label match, WITHOUT performing the full DB skeleton-collision
            scan. Useful for tuning the skeleton / reserved-label configuration
            without triggering spurious audit-log noise.

            <p>Requires <code>ROLE_ADMIN</code> (narrower than the class-level
            <code>ROLE_SERVICE</code> gate on the other endpoints — service tokens
            do not need this debug path).

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>ROLE_SERVICE</td><td>403</td></tr>
              <tr><td>ROLE_ADMIN / ROLE_SUPERADMIN</td>
                  <td>Skeleton + reserved match returned (no DB collision scan)</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Skeleton + reserved-match result returned. available=false when the "
                + "skeleton matches a reserved label; available=true otherwise (no DB scan — "
                + "does NOT confirm the username is free of existing-user collisions)."),
        @ApiResponse(responseCode = "400",
            description = "candidate path variable fails the DNS-label-token pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "Caller does not hold ROLE_ADMIN or ROLE_SUPERADMIN."),
        @ApiResponse(responseCode = "500",
            description = "Skeleton computation error. Check server logs.")
    })
    @GetMapping("/{candidate}/confusables")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<UsernameAvailabilityDto> confusables(
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String candidate) {
        // Reuse the check service with self=null and no override so this is a pure
        // skeleton/reserved probe — the ROLE_ADMIN gate is still enforced by
        // @PreAuthorize above. No DB scan, no override, no audit log entry.
        return availability.check(candidate, null);
    }

    // -------------------------------------------------------------------------
    // Shared check + optional override logic
    // -------------------------------------------------------------------------

    /**
     * Runs the availability check, then — when {@code override=confusable} is
     * supplied — gates the override on {@code ROLE_ADMIN}, applies it if the caller
     * qualifies, and writes an AUDIT log line if the verdict actually changed.
     *
     * <p>Non-admin callers who supply {@code override=confusable} receive the
     * UNMODIFIED verdict (the override is silently ignored, never an error). This
     * avoids leaking the existence of the override capability to service-token callers.
     *
     * @param candidate the username candidate
     * @param self      the caller's own username for self-exclusion (may be null)
     * @param override  {@code "confusable"} to request an admin override; any other
     *                  value or null skips the override path
     * @param jwt       the authenticated principal (may be null for service tokens
     *                  that reached here — the audit falls back to {@code "?"})
     * @return a {@code Mono<UsernameAvailabilityDto>} emitting the final verdict
     */
    private Mono<UsernameAvailabilityDto> checkAndMaybeOverride(
            String candidate, String self, String override, Jwt jwt) {
        Mono<UsernameAvailabilityDto> base = availability.check(candidate, self);
        if (!"confusable".equalsIgnoreCase(override)) {
            // No override requested — return the raw check result directly.
            return base;
        }
        // Override requested — require ROLE_ADMIN. A non-admin gets the unmodified
        // verdict (the override is silently ignored rather than a 403, so service-token
        // callers never discover the override capability).
        return base.flatMap(result -> isAdmin()
                // Apply the confusable override when the caller is an admin; audit on success.
                .map(admin -> applyOverrideIfAdmin(result, admin, jwt)));
    }

    /**
     * Applies the confusable override when {@code admin} is {@code true} and audits
     * every successful application; returns the unmodified {@code result} for non-admins.
     */
    private static UsernameAvailabilityDto applyOverrideIfAdmin(
            UsernameAvailabilityDto result, boolean admin, Jwt jwt) {
        if (!admin) {
            // Non-admin requested override → silently return the raw verdict.
            return result;
        }
        UsernameAvailabilityDto after = UsernameAvailabilityService.applyConfusableOverride(result);
        if (UsernameAvailabilityService.overrideApplied(result, after)) {
            // Audit EVERY successful override — the durable record of who overrode which
            // candidate and what the skeleton + prior collision was.
            AUDIT.warn("confusable-override actor={} candidate={} skeleton={} reason={} matchedWith={}",
                    jwt == null ? "?" : jwt.getSubject(),
                    result.candidate(), result.skeleton(), result.reason(), result.matchedWith());
        }
        return after;
    }

    /**
     * Returns {@code true} when the current reactive security context indicates the
     * caller holds {@code ROLE_ADMIN}. Non-blocking — reads from the reactive context
     * holder without touching the event loop.
     *
     * @return a {@code Mono<Boolean>} emitting {@code true} iff the caller is admin
     */
    private static Mono<Boolean> isAdmin() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())))
                .defaultIfEmpty(false);
    }
}
