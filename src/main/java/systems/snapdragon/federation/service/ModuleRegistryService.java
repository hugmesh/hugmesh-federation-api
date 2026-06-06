package systems.snapdragon.federation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.repository.FederationModuleRepository;

import java.time.Instant;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Registry CRUD for {@code federation_modules} — the admin-bff / owner-client
 * write surface. Reactive (Mono/Flux) throughout; sets the timestamp +
 * default-state fields on create the same way the games upload path inserts a
 * federation_modules row.
 */
@Service
public class ModuleRegistryService {

    private final FederationModuleRepository repo;

    public ModuleRegistryService(FederationModuleRepository repo) {
        this.repo = repo;
    }

    public Flux<FederationModule> list() {
        return repo.findAll();
    }

    public Mono<FederationModule> get(String slug) {
        return repo.findBySlug(slug)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)));
    }

    public Mono<FederationModule> create(FederationModule m) {
        Instant now = Instant.now();
        m.setId(null);
        if (m.getVisibility() == null) m.setVisibility("public");
        if (m.getCircuitState() == null) m.setCircuitState("closed");
        m.setCreatedAt(now);
        m.setUpdatedAt(now);
        return repo.save(m);
    }

    public Mono<FederationModule> update(String slug, FederationModule patch) {
        return repo.findBySlug(slug)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                .flatMap(existing -> {
                    if (patch.getDisplayName() != null) existing.setDisplayName(patch.getDisplayName());
                    if (patch.getKind() != null) existing.setKind(patch.getKind());
                    if (patch.getRemoteEntryUrl() != null) existing.setRemoteEntryUrl(patch.getRemoteEntryUrl());
                    if (patch.getExposedModule() != null) existing.setExposedModule(patch.getExposedModule());
                    if (patch.getVersion() != null) existing.setVersion(patch.getVersion());
                    if (patch.getContentHash() != null) existing.setContentHash(patch.getContentHash());
                    if (patch.getVisibility() != null) existing.setVisibility(patch.getVisibility());
                    if (patch.getCircuitState() != null) existing.setCircuitState(patch.getCircuitState());
                    if (patch.getMetadata() != null) existing.setMetadata(patch.getMetadata());
                    existing.setEnabled(patch.isEnabled());
                    existing.setUpdatedAt(Instant.now());
                    return repo.save(existing);
                });
    }

    public Mono<Void> delete(String slug) {
        return repo.findBySlug(slug)
                .switchIfEmpty(Mono.error(new ResponseStatusException(NOT_FOUND, "no module: " + slug)))
                .flatMap(repo::delete);
    }
}
