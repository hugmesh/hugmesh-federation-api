package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.model.SystemFinding;
import systems.snapdragon.federation.repository.SystemFindingRepository;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * The system-finding queue: AUTOMATED edge-AI moderation findings (avatar/image vision)
 * are FILED here {@code held}, and human moderators LIST + RESOLVE them.
 *
 * <h2>Responsibility</h2>
 * <p>Separate from {@link ModerationService} (the human recommend/refer/decide workflow
 * over federation actions): this queue is the sink for upstream automated checks. The
 * producer is the pre-publish vision-moderation gate (user-bff); the consumers are
 * mods/admins reviewing flagged content. The {@code subject} (content owner) is always
 * the producer's authenticated subject — never a body field — so a caller can only file
 * a finding about THEIR OWN content.
 *
 * <pre>
 *  Role            │ file (POST)  │ list        │ resolve
 *  ────────────────┼──────────────┼─────────────┼──────────────
 *  ROLE_USER       │ own subject  │ —           │ —
 *  ROLE_MOD/ADMIN  │ own subject  │ own domain  │ own domain
 *  ROLE_SUPERADMIN │ own subject  │ ALL domains │ ALL domains
 * </pre>
 *
 * @see SystemFindingRepository
 * @see SystemFinding
 * @see ModerationService
 */
@Service
public class SystemFindingService {

    private final SystemFindingRepository repo;

    public SystemFindingService(SystemFindingRepository repo) {
        this.repo = repo;
    }

    // ----- File (producer) -----

    /**
     * File a system finding {@code held} for review. {@code subject} is the producer's
     * authenticated Casdoor subject (the content owner) — never a request field.
     *
     * @param subject        the content owner (the caller's JWT subject)
     * @param surface        where the content was set ({@code profile-avatar}, ...)
     * @param disposition    {@code flagged} | {@code rejected}
     * @param classification edge-AI class ({@code safe|nsfw|abuse|unknown}); may be null
     * @param confidence     edge-AI confidence in {@code [0,1]}; may be null
     * @param policyHit      whether a policy threshold was crossed; may be null
     * @param perceptualHash pHash of the image; may be null
     * @param subjectRef     OPTIONAL back-reference to the EXACT source row (a
     *                       character-part / sticker id) for part-activation correlation;
     *                       null for the surface-level avatar/profile path (unaffected)
     * @param scope          the producer's resolved tenant scope (stamps {@code domain})
     * @return the saved {@link SystemFinding} with {@code reporter=@system}, {@code status=held}
     * @throws ResponseStatusException 400 when {@code surface}/{@code disposition} are invalid
     */
    public Mono<SystemFinding> file(String subject, String surface, String disposition,
                                    String classification, Double confidence, Boolean policyHit,
                                    String perceptualHash, String subjectRef, PrincipalDomain scope) {
        if (subject == null || subject.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "missing subject"));
        }
        if (surface == null || surface.isBlank()) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST, "surface is required"));
        }
        if (!isDisposition(disposition)) {
            return Mono.error(new ResponseStatusException(BAD_REQUEST,
                    "disposition must be flagged | rejected"));
        }
        SystemFinding f = new SystemFinding();
        f.setReporter("@system");
        f.setSubject(subject);
        f.setSurface(surface);
        f.setDisposition(disposition);
        f.setClassification(classification);
        f.setConfidence(confidence);
        f.setPolicyHit(policyHit);
        f.setPerceptualHash(perceptualHash);
        f.setSubjectRef(subjectRef);
        f.setStatus("held");
        f.setDomain(domainForWrite(scope));
        f.setTs(Instant.now());
        return repo.save(f);
    }

    // ----- List (consumer) -----

    /** All findings in scope, newest-first. Per-domain mod = own brand; SUPERADMIN = all. */
    public Flux<SystemFinding> list(PrincipalDomain scope) {
        return scope.superadmin()
                ? repo.findAllByOrderByTsDesc()
                : repo.findByDomainOrderByTsDesc(scope.domain());
    }

    /** Findings in scope filtered by review status, newest-first. */
    public Flux<SystemFinding> listByStatus(String status, PrincipalDomain scope) {
        return scope.superadmin()
                ? repo.findByStatusOrderByTsDesc(status)
                : repo.findByStatusAndDomainOrderByTsDesc(status, scope.domain());
    }

    // ----- Resolve (consumer) -----

    /**
     * Resolve a {@code held} finding: a mod marks it {@code dismissed} (cleared) or
     * {@code actioned} (action taken). Loaded domain-pinned so a per-domain mod can
     * never resolve another brand's finding (cross-domain id → 404).
     *
     * @param id        the finding id
     * @param actioned  {@code true} → {@code actioned}; {@code false} → {@code dismissed}
     * @param reviewer  the resolving mod's Casdoor subject
     * @param scope     the caller's resolved tenant scope (pins the load)
     */
    public Mono<SystemFinding> resolve(Long id, boolean actioned, String reviewer, PrincipalDomain scope) {
        return load(id, scope).flatMap(f -> {
            f.setStatus(actioned ? "actioned" : "dismissed");
            f.setReviewer(reviewer);
            f.setTs(Instant.now());
            return repo.save(f);
        });
    }

    // ----- Helpers -----

    private Mono<SystemFinding> load(Long id, PrincipalDomain scope) {
        Mono<SystemFinding> found = scope.superadmin()
                ? repo.findById(id)
                : repo.findByIdAndDomain(id, scope.domain());
        return found.switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no finding: " + id)));
    }

    private static String domainForWrite(PrincipalDomain scope) {
        return scope.superadmin() ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    private static boolean isDisposition(String d) {
        return "flagged".equals(d) || "rejected".equals(d);
    }
}
