package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import systems.snapdragon.federation.model.CapabilityDto;
import systems.snapdragon.federation.service.CapabilityService;

/**
 * PUBLIC capability projection — {@code GET /api/federation/capabilities}.
 *
 * <p>The install-state list a LOGGED-OUT or non-admin host reads to grey-out
 * OPTIONAL services (forum / mastodon / matrix / games) that are absent or
 * disabled. This is the public sibling of {@code GET /api/federation/manifest}:
 * the manifest is {@code authenticated()} + visibility-filtered (anonymous → 401,
 * and internal remotes are stripped for non-admins), so a logged-out host could
 * never learn an optional service exists — it CANNOT drive greying. This endpoint
 * is {@code permitAll} (see {@link systems.snapdragon.federation.config.SecurityConfig};
 * declared BEFORE the authenticated catch-all, exactly like the
 * {@code /api/federation/vanity} public read rule) and returns a deliberately
 * NARROW, public-safe projection (slug + installed + mountAt + requiresRole only —
 * no internal locator/detail).
 *
 * <p>GET-only so it can never mutate, and caller-independent (the same body for
 * everyone), so it is safe to serve with no JWT. The manifest / override read paths
 * are untouched: this is purely additive.
 */
@Tag(name = "Capabilities",
        description = "PUBLIC install-state projection (slug + installed + mountAt + requiresRole). "
                + "Drives host greying-out of absent/disabled optional services. Public read — no JWT.")
@RestController
@RequestMapping("/api/federation/capabilities")
public class CapabilityController {

    private final CapabilityService capabilities;

    public CapabilityController(CapabilityService capabilities) {
        this.capabilities = capabilities;
    }

    @Operation(
        summary = "Public install-state list of registered federation modules.",
        description = """
            Returns one public-safe descriptor per registered federation module —
            {slug, installed, mountAt, requiresRole} — ordered by slug. `installed`
            is true when the module's row is enabled AND circuit-closed (serveable
            right now). An OPTIONAL service that was never registered is ABSENT from
            the list (host greys it out by absence); a registered-but-disabled /
            circuit-broken one appears with installed=false (host greys it out by
            state). Public read — no JWT, no internal locator/detail. The host uses
            this (NOT the authed, visibility-filtered manifest) to grey-out absent
            services.
            """)
    @GetMapping
    public Flux<CapabilityDto> capabilities() {
        return capabilities.capabilities();
    }
}
