package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.VanityProfileDto;
import systems.snapdragon.federation.service.VanityService;

import java.util.Set;

/**
 * Vanity-subdomain resolve — the PUBLIC read path behind
 * {@code <username>.snapdragon.systems}.
 *
 * <p>Two shapes of the same resolve:
 * <ul>
 *   <li>{@code GET /api/federation/vanity/{username}} — explicit username (used by
 *       tooling + the fe-gateway when it extracts the first DNS label and rewrites
 *       the path);</li>
 *   <li>{@code GET /api/federation/vanity} with a {@code Host:} header — the
 *       federation API extracts the username itself from the FIRST DNS LABEL of the
 *       host ({@code alice.snapdragon.systems -> alice}). This lets the gateway
 *       forward the vanity request verbatim (preserving Host) with NO rewrite.</li>
 * </ul>
 *
 * <p><b>Public read (NO JWT).</b> This is the public profile — anonymous browsers
 * hit it. {@link systems.snapdragon.federation.config.SecurityConfig} permits
 * {@code GET /api/federation/vanity/**} for all. It is safe because the resolve
 * ONLY ever returns a {@code visibility='public'} + enabled + circuit-closed
 * fragment (enforced in the query AND re-asserted in {@link VanityService}); an
 * internal / disabled / missing / non-public username yields 404. It never reaches
 * the manifest's internal rows.
 *
 * <p>Reserved service subdomains ({@code id. api. matrix. mastodon. scale.
 * headscale.} + the apex) are matched by MORE-SPECIFIC gateway routes BEFORE the
 * {@code *.snapdragon.systems} wildcard, so they never arrive here; this controller
 * additionally refuses a reserved first-label defensively.
 */
@Tag(name = "Vanity", description = "Resolve <username>.<domain> to the user's PUBLIC profile fragment. Public read.")
@RestController
@RequestMapping("/api/federation/vanity")
public class VanityController {

    /**
     * Reserved first DNS labels that are platform service subdomains, NOT
     * usernames. The gateway route order already prevents these from reaching the
     * wildcard route; this is defence-in-depth so a direct call with a reserved
     * Host can never resolve a "user" named e.g. {@code api}.
     */
    static final Set<String> RESERVED_LABELS = Set.of(
            "id", "api", "matrix", "mastodon", "scale", "headscale", "www");

    private final VanityService vanity;

    public VanityController(VanityService vanity) {
        this.vanity = vanity;
    }

    @Operation(
        summary = "Resolve a username to its PUBLIC profile fragment descriptor.",
        description = """
            Returns the public profile-fragment locator (remoteEntryUrl,
            contentHash, the /_fragments/<slug>/<hash>/ static path) for
            <username> IFF a public, enabled, circuit-closed profile fragment
            (slug=profile-<username>, kind=fragment, visibility=public) exists;
            otherwise 404. Public read — no JWT. Never returns internal fragments.
            """)
    @GetMapping("/{username}")
    public Mono<VanityProfileDto> resolve(@PathVariable String username) {
        return resolveLabel(username);
    }

    @Operation(
        summary = "Resolve by Host header (first DNS label = username).",
        description = """
            Extracts the username from the FIRST DNS LABEL of the Host header
            (alice.snapdragon.systems -> alice) and resolves as above. Lets the
            gateway forward the vanity host verbatim with no path rewrite. 404 if
            the host has no sub-label (apex), is a reserved service subdomain, or
            has no public profile fragment.
            """)
    @GetMapping
    public Mono<VanityProfileDto> resolveByHost(@RequestHeader(value = "Host", required = false) String host) {
        String label = firstLabel(host);
        if (label == null) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "no vanity username in host: " + host));
        }
        return resolveLabel(label);
    }

    /** Shared resolve: reject reserved labels, then resolve-or-404. */
    private Mono<VanityProfileDto> resolveLabel(String label) {
        if (label != null && RESERVED_LABELS.contains(label.toLowerCase())) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "reserved subdomain, not a vanity username: " + label));
        }
        return vanity.resolve(label)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "no public profile for: " + label)));
    }

    /**
     * The first DNS label of a Host header — the vanity username. Strips a
     * {@code :port}, lower-cases, and requires at least one sub-label before the
     * registrable domain (so the apex {@code snapdragon.systems} returns null, not
     * the label {@code snapdragon}). Package-private + static for direct unit test.
     */
    static String firstLabel(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        String h = host.trim().toLowerCase();
        int colon = h.indexOf(':');
        if (colon >= 0) {
            h = h.substring(0, colon);
        }
        String[] labels = h.split("\\.");
        // A vanity host has at least 3 labels: <user>.<domain>.<tld>. With exactly
        // 2 (the apex domain.tld) there is no username -> null.
        if (labels.length < 3 || labels[0].isBlank()) {
            return null;
        }
        return labels[0];
    }
}
