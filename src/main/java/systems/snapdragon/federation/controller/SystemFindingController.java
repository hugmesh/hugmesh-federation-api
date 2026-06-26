package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
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
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.PrincipalDomain;
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
     */
    public record FileRequest(
            @NotBlank(message = "surface is required")
            @Size(max = 64, message = "surface must be at most 64 chars") String surface,
            @NotBlank(message = "disposition is required")
            @Pattern(regexp = "flagged|rejected", message = "disposition must be flagged | rejected") String disposition,
            @Size(max = 32, message = "classification must be at most 32 chars") String classification,
            Double confidence,
            Boolean policyHit,
            @Size(max = 128, message = "perceptualHash must be at most 128 chars") String perceptualHash) {}

    @Operation(summary = "File a system moderation finding about my own content (subject = JWT subject; reporter = @system).")
    @PostMapping
    @PreAuthorize("isAuthenticated()")
    public Mono<SystemFinding> file(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody FileRequest req) {
        // subject = the authenticated JWT subject (the content owner), never the body.
        return findings.file(jwt.getSubject(), req.surface(), req.disposition(),
                req.classification(), req.confidence(), req.policyHit(), req.perceptualHash(),
                PrincipalDomain.resolve(jwt, domains));
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
}
