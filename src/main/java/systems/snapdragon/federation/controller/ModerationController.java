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
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.security.DomainRegistry;
import systems.snapdragon.federation.security.DomainScope;
import systems.snapdragon.federation.service.ModerationService;
import systems.snapdragon.federation.web.ValidationPatterns;

/**
 * The moderation workflow surface — recommend / refer / decide. Mirrors the games
 * ModerationController's ROLE_MOD / ROLE_ADMIN split:
 *
 * <ul>
 *   <li>submit + refer = ROLE_MOD or ROLE_ADMIN (a mod opens / escalates);</li>
 *   <li>decide = ROLE_ADMIN only (an admin approves / denies).</li>
 * </ul>
 *
 * Enforced by {@code @PreAuthorize} (method security) + the path rules in
 * SecurityConfig.
 */
@Tag(name = "Moderation", description = "Recommend / refer / decide moderation workflow. ROLE_MOD submits/refers, ROLE_ADMIN decides.")
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

    /**
     * The submit body. {@code kind} must be one of the {@code moderation_requests.kind}
     * vocabulary (mirrors the 018 CHECK + {@code ModerationService.isKind}) and
     * {@code target} (the instance host / user id the action is aimed at) is a
     * NOT-NULL DB column, so both are required here for a clean 400 before the DB.
     */
    public record SubmitRequest(
            @NotBlank(message = "kind is required")
            @Pattern(regexp = ValidationPatterns.MODERATION_KIND,
                    message = "kind must be instance-block|user-removal") String kind,
            @NotBlank(message = "target is required")
            @Size(max = 1024, message = "target must be at most 1024 chars") String target,
            @Size(max = 1024, message = "reason must be at most 1024 chars") String reason) {}

    @Operation(summary = "List moderation requests in the caller's domain (SUPERADMIN: all; optionally by status).")
    @GetMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Flux<ModerationRequest> list(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(required = false)
            @Pattern(regexp = ValidationPatterns.MODERATION_STATUS,
                    message = "status must be recommended|referred|approved|denied") String status) {
        DomainScope scope = DomainScope.resolve(jwt, domains);
        return status == null ? moderation.list(scope) : moderation.listByStatus(status, scope);
    }

    @Operation(summary = "Submit a moderation request (mod recommends; stamped with the caller's domain).")
    @PostMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Mono<ModerationRequest> submit(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody SubmitRequest req) {
        return moderation.submit(jwt.getSubject(), req.kind(), req.target(), req.reason(),
                DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Refer a request up to admins (mod escalates; scoped to the caller's domain).")
    @PostMapping("/{id}/refer")
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    public Mono<ModerationRequest> refer(@AuthenticationPrincipal Jwt jwt,
                                         @PathVariable @Positive(message = "id must be a positive number") Long id) {
        return moderation.refer(id, jwt.getSubject(), DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Decide a request (admin approves / denies; scoped to the caller's domain).")
    @PostMapping("/{id}/decide")
    @PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
    public Mono<ModerationRequest> decide(@AuthenticationPrincipal Jwt jwt,
                                          @PathVariable @Positive(message = "id must be a positive number") Long id,
                                          @RequestParam boolean approve) {
        return moderation.decide(id, approve, jwt.getSubject(), DomainScope.resolve(jwt, domains));
    }
}
