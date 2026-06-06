package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.service.ModuleRegistryService;

/**
 * Module registry CRUD — the admin-bff / owner-client write surface for
 * {@code federation_modules}. ROLE_ADMIN gated (defence-in-depth on top of the
 * gateway), enforced by {@code @PreAuthorize} (method security) AND the path
 * rule in SecurityConfig.
 */
@Tag(name = "Module Registry", description = "Federation module registry CRUD. ROLE_ADMIN required.")
@RestController
@RequestMapping("/api/federation/modules")
@PreAuthorize("hasRole('ADMIN')")
public class ModuleRegistryController {

    private final ModuleRegistryService registry;

    public ModuleRegistryController(ModuleRegistryService registry) {
        this.registry = registry;
    }

    @Operation(summary = "List every registered module (admin view, unfiltered).")
    @GetMapping
    public Flux<FederationModule> list() {
        return registry.list();
    }

    @Operation(summary = "Get one module by slug.")
    @GetMapping("/{slug}")
    public Mono<FederationModule> get(@PathVariable String slug) {
        return registry.get(slug);
    }

    @Operation(summary = "Register a new module.")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<FederationModule> create(@RequestBody FederationModule module) {
        return registry.create(module);
    }

    @Operation(summary = "Update a module by slug (partial — non-null fields win).")
    @PutMapping("/{slug}")
    public Mono<FederationModule> update(@PathVariable String slug, @RequestBody FederationModule patch) {
        return registry.update(slug, patch);
    }

    @Operation(summary = "Delete a module by slug.")
    @DeleteMapping("/{slug}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(@PathVariable String slug) {
        return registry.delete(slug);
    }
}
