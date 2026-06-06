package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.repository.ModerationRequestRepository;

import java.time.Instant;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * The recommend / refer / decide moderation workflow. Mirrors the games
 * ModerationController's ROLE_MOD-recommends / ROLE_ADMIN-decides split:
 *
 * <ol>
 *   <li>{@link #submit} — a mod opens a request (status {@code recommended}).</li>
 *   <li>{@link #refer}  — a mod refers it up to admins (status {@code referred}).</li>
 *   <li>{@link #decide} — an admin approves or denies it.</li>
 * </ol>
 *
 * <p>An {@code approved} request is the authorization for an
 * {@link OverrideService#apply} kill-switch action; wiring that auto-application
 * is left as a documented follow-up (see README) so the decision and the action
 * stay auditable as separate steps.
 */
@Service
public class ModerationService {

    private final ModerationRequestRepository repo;

    public ModerationService(ModerationRequestRepository repo) {
        this.repo = repo;
    }

    public Flux<ModerationRequest> list() {
        return repo.findAllByOrderByTsDesc();
    }

    public Flux<ModerationRequest> listByStatus(String status) {
        return repo.findByStatusOrderByTsDesc(status);
    }

    /** A mod opens a request. {@code requester} is the mod's Casdoor subject. */
    public Mono<ModerationRequest> submit(String requester, String kind, String target, String reason) {
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
        r.setTs(Instant.now());
        return repo.save(r);
    }

    /** A mod refers a recommended request up to admins. */
    public Mono<ModerationRequest> refer(Long id, String modReferrer) {
        return repo.findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no request: " + id)))
                .flatMap(r -> {
                    r.setStatus("referred");
                    r.setModReferrer(modReferrer);
                    r.setTs(Instant.now());
                    return repo.save(r);
                });
    }

    /** An admin decides: {@code approve=true} -> approved, else denied. */
    public Mono<ModerationRequest> decide(Long id, boolean approve, String adminDecider) {
        return repo.findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no request: " + id)))
                .flatMap(r -> {
                    r.setStatus(approve ? "approved" : "denied");
                    r.setAdminDecider(adminDecider);
                    r.setTs(Instant.now());
                    return repo.save(r);
                });
    }

    private static boolean isKind(String k) {
        return "instance-block".equals(k) || "user-removal".equals(k);
    }
}
