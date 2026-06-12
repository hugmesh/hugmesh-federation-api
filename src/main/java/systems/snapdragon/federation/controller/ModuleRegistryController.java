package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.security.DomainRegistry;
import systems.snapdragon.federation.security.DomainScope;
import systems.snapdragon.federation.service.ModuleRegistryService;
import systems.snapdragon.federation.web.ValidationPatterns;

/**
 * Module registry CRUD — the admin-bff / owner-client write surface for
 * {@code federation_modules}. ROLE_ADMIN gated (defence-in-depth on top of the
 * gateway), enforced by {@code @PreAuthorize} (method security) AND the path
 * rule in SecurityConfig.
 */
@Tag(name = "Module Registry", description = "Federation module registry CRUD. ROLE_ADMIN required.")
@RestController
@RequestMapping("/api/federation/modules")
@PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")
@Validated
public class ModuleRegistryController {

    private final ModuleRegistryService registry;
    private final DomainRegistry domains;

    public ModuleRegistryController(ModuleRegistryService registry, DomainRegistry domains) {
        this.registry = registry;
        this.domains = domains;
    }

    @Operation(summary = "List registered modules in the caller's domain (SUPERADMIN: all).")
    @GetMapping
    public Flux<FederationModule> list(@AuthenticationPrincipal Jwt jwt) {
        return registry.list(DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Get one module by slug (scoped to the caller's domain; SUPERADMIN: any).")
    @GetMapping("/{slug}")
    public Mono<FederationModule> get(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        return registry.get(slug, DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Register a new module (stamped with the caller's domain).")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<FederationModule> create(
            @AuthenticationPrincipal Jwt jwt,
            @Validated(FederationModule.OnCreate.class) @RequestBody FederationModule module) {
        return registry.create(module, DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Update a module by slug (partial; scoped to the caller's domain; SUPERADMIN: any).")
    @PutMapping("/{slug}")
    public Mono<FederationModule> update(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug,
            @Valid @RequestBody FederationModule patch) {
        return registry.update(slug, patch, DomainScope.resolve(jwt, domains));
    }

    @Operation(summary = "Delete a module by slug (scoped to the caller's domain; SUPERADMIN: any).")
    @DeleteMapping("/{slug}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> delete(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        return registry.delete(slug, DomainScope.resolve(jwt, domains));
    }
}
