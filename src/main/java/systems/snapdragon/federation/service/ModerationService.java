package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.repository.ModerationRequestRepository;
import systems.snapdragon.commons.security.PrincipalDomain;

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

    /** DOMAIN-scoped workflow list. A per-domain mod/admin sees ONLY their own
     *  brand's requests; SUPERADMIN sees every request across all brands. */
    public Flux<ModerationRequest> list(PrincipalDomain scope) {
        return scope.superadmin()
                ? repo.findAllByOrderByTsDesc()
                : repo.findByDomainOrderByTsDesc(scope.domain());
    }

    /** DOMAIN-scoped workflow list filtered by status. */
    public Flux<ModerationRequest> listByStatus(String status, PrincipalDomain scope) {
        return scope.superadmin()
                ? repo.findByStatusOrderByTsDesc(status)
                : repo.findByStatusAndDomainOrderByTsDesc(status, scope.domain());
    }

    /**
     * A mod opens a request IN THEIR DOMAIN. {@code requester} is the mod's Casdoor
     * subject; the row is stamped with the requester's domain (NEVER a body value) so
     * the request is visible only to staff of the same brand. A SUPERADMIN submit
     * (no domain in scope) lands in {@code "default"}.
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
     * A mod refers a recommended request up to admins. The request is loaded pinned
     * to the caller's domain so a per-domain mod can NEVER refer another brand's
     * request (a cross-domain id -> 404). SUPERADMIN refers any request.
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
     * An admin decides: {@code approve=true} -> approved, else denied. The request is
     * loaded pinned to the caller's domain so a per-domain admin can NEVER decide
     * another brand's request (cross-domain id -> 404). SUPERADMIN decides any
     * request.
     */
    public Mono<ModerationRequest> decide(Long id, boolean approve, String adminDecider, PrincipalDomain scope) {
        return load(id, scope)
                .flatMap(r -> {
                    r.setStatus(approve ? "approved" : "denied");
                    r.setAdminDecider(adminDecider);
                    r.setTs(Instant.now());
                    return repo.save(r);
                });
    }

    /** Load a request by id, domain-pinned for a per-domain principal (SUPERADMIN:
     *  any). 404 when absent OR when it belongs to another brand (the cross-domain
     *  finder returns empty). */
    private Mono<ModerationRequest> load(Long id, PrincipalDomain scope) {
        Mono<ModerationRequest> found = scope.superadmin()
                ? repo.findById(id)
                : repo.findByIdAndDomain(id, scope.domain());
        return found.switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no request: " + id)));
    }

    /** The domain to stamp on a written request: the requester's domain, or
     *  {@code "default"} for a SUPERADMIN submit (no domain in scope). */
    private static String domainForWrite(PrincipalDomain scope) {
        return scope.superadmin() ? PrincipalDomain.forDomain("default").domain() : scope.domain();
    }

    private static boolean isKind(String k) {
        return "instance-block".equals(k) || "user-removal".equals(k);
    }
}
