package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
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
import systems.snapdragon.federation.model.UsernameAvailabilityDto;
import systems.snapdragon.federation.service.UsernameAvailabilityService;
import systems.snapdragon.federation.web.ValidationPatterns;

/**
 * Username availability / confusable CHECK — the registry-owned look-alike gate.
 *
 * <h2>INTERNAL / ROLE_SERVICE — NOT public</h2>
 * Every endpoint here is an ENUMERATION ORACLE ({@code matchedWith} names the
 * colliding username / reserved label), so the whole controller is gated to an
 * internal service credential ({@code ROLE_SERVICE}) — never the SPA / public
 * surface. {@code SecurityConfig} path-gates {@code /api/federation/username/**} to
 * {@code ROLE_SERVICE} (or {@code ROLE_ADMIN} for the override + debug endpoint),
 * and the {@code @PreAuthorize} here is defence-in-depth on top of that.
 *
 * <ul>
 *   <li>{@code GET /{candidate}/availability} — the registration gate. The mint
 *       paths (Casdoor pre-signup webhook, OAuth provider-handle mint, actions /
 *       user-bff / admin-bff) call this before granting a username.</li>
 *   <li>{@code POST /check} — same check by request body (a candidate + optional
 *       self username), for callers that prefer a POST.</li>
 *   <li>{@code GET /{candidate}/confusables} — ADMIN debug: the computed skeleton
 *       (+ any reserved match) with no DB collision scan, for tuning.</li>
 * </ul>
 *
 * <p>{@code self} excludes the caller's OWN existing username by EXACT username
 * only (a different-but-confusable owner stays flagged). {@code override=confusable}
 * (ROLE_ADMIN only) flips an {@code exact}/{@code confusable} verdict to available
 * and writes an AUDIT line; it NEVER overrides {@code reserved} or a hard reject.
 */
@Tag(name = "Username", description = "Username availability + confusable check. INTERNAL / ROLE_SERVICE.")
@RestController
@RequestMapping("/api/federation/username")
@PreAuthorize("hasAnyRole('SERVICE', 'ADMIN')")
@Validated
public class UsernameAvailabilityController {

    /** Structured AUDIT logger — the durable record of a ROLE_ADMIN confusable
     *  override (a non-destructive event; there is no domain row to mutate). */
    private static final Logger AUDIT = LoggerFactory.getLogger("systems.snapdragon.federation.AUDIT");

    private final UsernameAvailabilityService availability;

    public UsernameAvailabilityController(UsernameAvailabilityService availability) {
        this.availability = availability;
    }

    @Operation(summary = "Check whether a candidate username is available (collision / reserved / confusable).")
    @GetMapping("/{candidate}/availability")
    public Mono<UsernameAvailabilityDto> availability(
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String candidate,
            @RequestParam(value = "self", required = false) String self,
            @RequestParam(value = "override", required = false) String override,
            @AuthenticationPrincipal Jwt jwt) {
        return checkAndMaybeOverride(candidate, self, override, jwt);
    }

    /** POST body for {@code /check}. */
    public record CheckRequest(String candidate, String self, String override) {}

    @Operation(summary = "Check a candidate username by request body.")
    @PostMapping("/check")
    public Mono<UsernameAvailabilityDto> check(@RequestBody CheckRequest req,
                                               @AuthenticationPrincipal Jwt jwt) {
        return checkAndMaybeOverride(req.candidate(), req.self(), req.override(), jwt);
    }

    @Operation(summary = "ADMIN debug: the computed skeleton (+ any reserved match) for a candidate, no DB scan.")
    @GetMapping("/{candidate}/confusables")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<UsernameAvailabilityDto> confusables(
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String candidate) {
        // Reuse the check but force self=null + no override so it is a pure
        // skeleton/reserved probe (the controller still gates ADMIN).
        return availability.check(candidate, null);
    }

    /**
     * Run the check, then — only when {@code override=confusable} is requested — gate
     * the override on ROLE_ADMIN, apply it, and AUDIT it if it actually changed the
     * verdict. The override never weakens reserved / exact-DB / hard-reject rules.
     */
    private Mono<UsernameAvailabilityDto> checkAndMaybeOverride(
            String candidate, String self, String override, Jwt jwt) {
        Mono<UsernameAvailabilityDto> base = availability.check(candidate, self);
        if (!"confusable".equalsIgnoreCase(override)) {
            return base;
        }
        // Override requested — require ROLE_ADMIN; non-admins get the un-overridden
        // verdict (the override is silently ignored, never an error that leaks).
        return base.flatMap(result -> isAdmin().map(admin -> {
            if (!admin) {
                return result;
            }
            UsernameAvailabilityDto after = UsernameAvailabilityService.applyConfusableOverride(result);
            if (UsernameAvailabilityService.overrideApplied(result, after)) {
                AUDIT.warn("confusable-override actor={} candidate={} skeleton={} reason={} matchedWith={}",
                        jwt == null ? "?" : jwt.getSubject(),
                        result.candidate(), result.skeleton(), result.reason(), result.matchedWith());
            }
            return after;
        }));
    }

    private static Mono<Boolean> isAdmin() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())))
                .defaultIfEmpty(false);
    }
}
