package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.model.ResolvedFindingView;
import systems.snapdragon.federation.model.SystemFinding;
import systems.snapdragon.federation.service.SystemFindingService;

/**
 * The SYSTEM-FINDING queue surface — automated edge-AI moderation findings (avatar/image
 * vision) are FILED here, and human moderators LIST + RESOLVE them.
 *
 * <h2>Security gating</h2>
 * <ul>
 *   <li><b>File</b> ({@code POST /}) — any authenticated caller (typically a BFF acting
 *       on a user's session) files a finding about THEIR OWN content: the {@code subject}
 *       is the JWT subject, never a body field, so a caller can only ever file about
 *       themselves. {@code reporter} is always {@code @system}.</li>
 *   <li><b>List</b> ({@code GET /}) + <b>Resolve</b> ({@code POST /{id}/resolve}) —
 *       {@code ROLE_MOD} / {@code ROLE_ADMIN} / {@code ROLE_SUPERADMIN} only (path rules
 *       in {@link systems.snapdragon.federation.config.SecurityConfig} + method-security
 *       here, defence-in-depth).</li>
 * </ul>
 *
 * <h2>Domain scoping</h2>
 * <p>Every operation is DOMAIN-scoped from the validated JWT issuer via
 * {@link PrincipalDomain#resolve}. A per-domain mod sees + resolves ONLY their own
 * brand's findings; SUPERADMIN spans all brands.
 *
 * @see SystemFindingService
 */
@Tag(name = "System Findings",
        description = "Automated edge-AI moderation findings (avatar/image vision). "
                + "Any authenticated caller files about their OWN content; ROLE_MOD lists + resolves. DOMAIN-scoped.")
@RestController
@RequestMapping("/api/federation/findings")
@Validated
public class SystemFindingController {

    private final SystemFindingService findings;
    private final DomainRegistry domains;

    public SystemFindingController(SystemFindingService findings, DomainRegistry domains) {
        this.findings = findings;
        this.domains = domains;
    }

    /**
     * Body for {@code POST /} — a system finding about the caller's own content. The
     * {@code subject} is NOT a field here: it is the authenticated JWT subject.
     *
     * @param surface        where the content was set ({@code profile-avatar}, ...)
     * @param disposition    {@code flagged} (queued) | {@code rejected} (blocked)
     * @param classification edge-AI class ({@code safe|nsfw|abuse|unknown}); optional
     * @param confidence     edge-AI confidence in {@code [0,1]}; optional
     * @param policyHit      whether a policy threshold was crossed; optional
     * @param perceptualHash pHash of the image; optional
     * @param subjectRef     OPTIONAL back-reference to the EXACT source row this finding
     *                       is about (a character-part / sticker id) for part-activation
     *                       correlation; null for the surface-level avatar/profile path
     */
    public record FileRequest(
            @NotBlank(message = "surface is required")
            @Size(max = 64, message = "surface must be at most 64 chars") String surface,
            @NotBlank(message = "disposition is required")
            @Pattern(regexp = "flagged|rejected", message = "disposition must be flagged | rejected") String disposition,
            @Size(max = 32, message = "classification must be at most 32 chars") String classification,
            Double confidence,
            Boolean policyHit,
            @Size(max = 128, message = "perceptualHash must be at most 128 chars") String perceptualHash,
            @Size(max = 128, message = "subjectRef must be at most 128 chars") String subjectRef) {}

    @Operation(summary = "File a system moderation finding about my own content (subject = JWT subject; reporter = @system).")
    @PostMapping
    @PreAuthorize("isAuthenticated()")
    public Mono<SystemFinding> file(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody FileRequest req) {
        // subject = the authenticated JWT subject (the content owner), never the body.
        return findings.file(jwt.getSubject(), req.surface(), req.disposition(),
                req.classification(), req.confidence(), req.policyHit(), req.perceptualHash(),
                req.subjectRef(), PrincipalDomain.resolve(jwt, domains));
    }

    @Operation(summary = "List system findings in my domain (SUPERADMIN: all domains). Optional ?status=held|dismissed|actioned.")
    @GetMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Flux<SystemFinding> list(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false)
            @Pattern(regexp = "held|dismissed|actioned",
                    message = "status must be held | dismissed | actioned") String status) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        return status == null ? findings.list(scope) : findings.listByStatus(status, scope);
    }

    @Operation(summary = "Resolve a held finding (mod): ?actioned=true marks it actioned, false dismisses it. Cross-domain id → 404.")
    @PostMapping("/{id}/resolve")
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Mono<SystemFinding> resolve(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Positive(message = "id must be a positive number") Long id,
            @RequestParam boolean actioned) {
        return findings.resolve(id, actioned, jwt.getSubject(), PrincipalDomain.resolve(jwt, domains));
    }

    /**
     * Cursor-paged RESOLVED-findings read for the admin-bff moderation → activation
     * reconciler (an internal @Scheduled poller). Returns the resolved
     * ({@code actioned}/{@code dismissed}) findings on {@code surface} that carry a
     * {@code subjectRef} (the user-bff row id) and have {@code id > sinceId}, id-ASC so
     * {@code id} is a monotonic watermark the reconciler advances each poll.
     *
     * <h3>Gating</h3>
     * <p>INTERNAL / service-to-service — {@code ROLE_SERVICE} (the platform reconciler's
     * token) or {@code ROLE_ADMIN}/{@code ROLE_SUPERADMIN}, mirroring the
     * {@code /api/federation/username/**} internal convention (path rule in
     * {@link systems.snapdragon.federation.config.SecurityConfig} + this method gate,
     * defence-in-depth). NOT a public / ROLE_USER / ROLE_MOD surface.
     *
     * <h3>Domain scope</h3>
     * <p>A SERVICE token (the platform reconciler) or a SUPERADMIN reads CROSS-DOMAIN —
     * it must close the activation loop for every brand. A per-domain ADMIN reads ONLY
     * its own brand's resolved findings.
     *
     * @param surface the surface to scope to ({@code character-part} / {@code character-sticker})
     * @param sinceId the watermark — only findings with {@code id > sinceId} (default 0)
     * @param limit   page size (default {@value SystemFindingService#DEFAULT_RECONCILE_LIMIT},
     *                capped at {@value SystemFindingService#MAX_RECONCILE_LIMIT})
     */
    @Operation(summary = "INTERNAL (ROLE_SERVICE/ADMIN/SUPERADMIN): cursor-paged resolved findings on a surface "
            + "(id > sinceId, subjectRef present) for the moderation → activation reconciler. "
            + "SERVICE/SUPERADMIN = cross-domain; per-domain ADMIN = own brand.")
    @GetMapping("/resolved")
    @PreAuthorize("hasAnyRole('SERVICE','ADMIN','SUPERADMIN')")
    public Flux<ResolvedFindingView> resolved(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam
            @NotBlank(message = "surface is required")
            @Size(max = 64, message = "surface must be at most 64 chars") String surface,
            @RequestParam(required = false, defaultValue = "0")
            @PositiveOrZero(message = "sinceId must be zero or positive") long sinceId,
            @RequestParam(required = false, defaultValue = "0")
            @PositiveOrZero(message = "limit must be zero or positive") int limit) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        // Cross-domain reader = the platform reconciler (a SERVICE token) OR a SUPERADMIN;
        // a per-domain ADMIN stays pinned to scope.domain(). Read from the granted
        // authorities on the reactive context (the SAME source the path/method gates use,
        // and exactly how UsernameAvailabilityController.isAdmin() resolves a role) so the
        // domain cut mirrors federation's "cross-domain infra role spans all brands"
        // contract whether the SERVICE/SUPERADMIN role arrives as an authority or a claim.
        return isCrossDomainReader()
                .flatMapMany(crossDomain ->
                        findings.resolvedForReconcile(surface, sinceId, limit, crossDomain, scope));
    }

    /**
     * Returns {@code true} when the caller is a CROSS-DOMAIN reader of resolved findings:
     * the platform reconciler ({@code ROLE_SERVICE}) or a {@code ROLE_SUPERADMIN}. A
     * per-domain {@code ROLE_ADMIN} returns {@code false} (stays pinned to its own brand).
     * Reads the granted authorities off the reactive security context, mirroring
     * {@code UsernameAvailabilityController.isAdmin()}.
     */
    private static Mono<Boolean> isCrossDomainReader() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .map(a -> a.getAuthority())
                        .anyMatch(a -> "ROLE_SERVICE".equals(a) || "ROLE_SUPERADMIN".equals(a)))
                .defaultIfEmpty(false);
    }
}
