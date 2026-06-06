package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.service.ModerationService;

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
public class ModerationController {

    private final ModerationService moderation;

    public ModerationController(ModerationService moderation) {
        this.moderation = moderation;
    }

    public record SubmitRequest(String kind, String target, String reason) {}

    @Operation(summary = "List moderation requests (optionally by status).")
    @GetMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    public Flux<ModerationRequest> list(@RequestParam(required = false) String status) {
        return status == null ? moderation.list() : moderation.listByStatus(status);
    }

    @Operation(summary = "Submit a moderation request (mod recommends).")
    @PostMapping
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    public Mono<ModerationRequest> submit(@AuthenticationPrincipal Jwt jwt, @RequestBody SubmitRequest req) {
        return moderation.submit(jwt.getSubject(), req.kind(), req.target(), req.reason());
    }

    @Operation(summary = "Refer a request up to admins (mod escalates).")
    @PostMapping("/{id}/refer")
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    public Mono<ModerationRequest> refer(@AuthenticationPrincipal Jwt jwt, @PathVariable Long id) {
        return moderation.refer(id, jwt.getSubject());
    }

    @Operation(summary = "Decide a request (admin approves / denies).")
    @PostMapping("/{id}/decide")
    @PreAuthorize("hasRole('ADMIN')")
    public Mono<ModerationRequest> decide(@AuthenticationPrincipal Jwt jwt,
                                          @PathVariable Long id,
                                          @RequestParam boolean approve) {
        return moderation.decide(id, approve, jwt.getSubject());
    }
}
