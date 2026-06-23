package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.VanityProfileDto;
import systems.snapdragon.federation.service.UsernameSkeletonService;
import systems.snapdragon.federation.service.VanityService;
import systems.snapdragon.federation.web.ValidationPatterns;

import static systems.snapdragon.federation.controller.ReservedNames.RESERVED_LABELS;

/**
 * Vanity-subdomain resolve — the PUBLIC read path behind
 * {@code <username>.snapdragon.systems}.
 *
 * <p>Exposes two shapes of the same resolve:
 * <ul>
 *   <li>{@code GET /api/federation/vanity/{username}} — explicit username in the
 *       path variable; used by tooling and by the fe-gateway when it extracts the
 *       first DNS label and rewrites the path.</li>
 *   <li>{@code GET /api/federation/vanity} with a {@code Host:} header — the API
 *       extracts the username itself from the FIRST DNS LABEL of the host
 *       ({@code alice.snapdragon.systems → alice}), letting the gateway forward
 *       the vanity request verbatim (preserving Host) with NO path rewrite.</li>
 * </ul>
 *
 * <h2>Security gating</h2>
 * <p>{@code GET /api/federation/vanity/**} is {@code permitAll} (see
 * {@link systems.snapdragon.federation.config.SecurityConfig}, declared BEFORE the
 * authenticated catch-alls). It is safe because:
 * <ul>
 *   <li>{@link VanityService} filters {@code visibility='public'} +
 *       {@code enabled=true} + {@code circuit_state='closed'} IN THE QUERY — an
 *       internal, disabled, or kill-switched fragment can never be returned.</li>
 *   <li>An owner under an active scope=user override (access-suspension) is
 *       additionally suppressed in {@link VanityService#resolve}, even when the
 *       fragment is public+enabled+closed.</li>
 *   <li>A non-existent / non-public username yields 404 — there is no oracle for
 *       whether a username exists (a reserved or confusable label also 404s).</li>
 *   <li>GET-only — this endpoint can never mutate state.</li>
 * </ul>
 *
 * <h2>Reserved-label defence (READ layer)</h2>
 * <p>Reserved service subdomains ({@code id. api. matrix. mastodon. scale.
 * headscale.} etc. and the apex) are matched by MORE-SPECIFIC gateway routes
 * BEFORE the {@code *.snapdragon.systems} wildcard, so they never arrive here.
 * Additionally, this controller:
 * <ol>
 *   <li>Rejects an EXACT reserved label (from {@link ReservedNames#RESERVED_LABELS}).</li>
 *   <li>Rejects a CONFUSABLE-of-reserved first label via the precomputed
 *       reserved-skeleton set ({@link UsernameSkeletonService#isReservedSkeleton} —
 *       O(1) membership check, no DB hit). This is defence-in-depth: even if a
 *       {@code profile-4dmin} fragment slipped past the write-layer gate (via
 *       backfill, a race, or an ICU shift), its vanity host still 404s here.</li>
 * </ol>
 *
 * @see VanityService
 * @see UsernameSkeletonService
 * @see systems.snapdragon.federation.config.SecurityConfig
 */
@Tag(name = "Vanity",
        description = "Resolve <username>.<domain> to the user's PUBLIC profile fragment. "
                + "Public read — no JWT required.")
@RestController
@RequestMapping("/api/federation/vanity")
@Validated
public class VanityController {

    /**
     * The vanity resolve service — returns ONLY public, enabled, circuit-closed
     * profile fragments. An internal / disabled / missing / banned-owner one yields
     * {@code Mono.empty()} → 404.
     */
    private final VanityService vanity;

    /**
     * The confusable-skeleton service. Its precomputed reserved-skeleton set drives
     * the READ-LAYER defence: an O(1) membership check on the first DNS label (no DB
     * hit) so a CONFUSABLE of a reserved label ({@code 4dmin}, {@code akk0ma}) that
     * somehow minted a {@code profile-<label>} slug — via backfill, a race, or an
     * ICU shift — still hard-404s here, not just an exact reserved label.
     */
    private final UsernameSkeletonService skeletons;

    public VanityController(VanityService vanity, UsernameSkeletonService skeletons) {
        this.vanity = vanity;
        this.skeletons = skeletons;
    }

    // -------------------------------------------------------------------------
    // Resolve by path variable
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Resolve a username to its PUBLIC profile fragment descriptor.",
        description = """
            Returns the public profile-fragment locator
            (<code>remoteEntryUrl, contentHash</code>, the
            <code>/_fragments/&lt;slug&gt;/&lt;hash&gt;/</code> static path) for
            <code>&lt;username&gt;</code> IFF a public, enabled, circuit-closed profile
            fragment (<code>slug=profile-&lt;username&gt;</code>,
            <code>kind=fragment</code>, <code>visibility=public</code>) exists AND
            the owner is not under an active access-suspension scope override.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller</th><th>Result</th></tr>
              <tr><td>Anyone (no JWT required)</td>
                  <td>Profile fragment descriptor if it exists and is public;
                      404 otherwise</td></tr>
            </table>

            <p>Never returns internal fragments. Reserved or confusable-of-reserved
            usernames are rejected with 404 (no DB lookup is needed or performed).
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Public profile fragment descriptor returned — "
                + "remoteEntryUrl, contentHash, static path."),
        @ApiResponse(responseCode = "400",
            description = "username path variable fails the DNS-label-token pattern."),
        @ApiResponse(responseCode = "404",
            description = "No public profile for that username — it does not exist, is not "
                + "public/enabled/circuit-closed, the owner is suspended, or the username is "
                + "a reserved / confusable-of-reserved label."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error during the resolve. Check server logs.")
    })
    @GetMapping("/{username}")
    public Mono<VanityProfileDto> resolve(
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String username) {
        return resolveLabel(username);
    }

    // -------------------------------------------------------------------------
    // Resolve by Host header (gateway verbatim-forward path)
    // -------------------------------------------------------------------------

    @Operation(
        summary = "Resolve by Host header (first DNS label = username).",
        description = """
            Extracts the username from the FIRST DNS LABEL of the
            <code>Host</code> header (<code>alice.snapdragon.systems → alice</code>)
            and resolves as the path-variable form above. Lets the gateway forward
            the vanity host verbatim with no path rewrite.

            <p>404 if:
            <ul>
              <li>The host has no sub-label (the bare apex — exactly 2 DNS labels).</li>
              <li>The first label is a reserved service subdomain or a confusable of one.</li>
              <li>No public profile fragment exists for the extracted username.</li>
            </ul>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Public profile fragment descriptor returned — "
                + "remoteEntryUrl, contentHash, static path."),
        @ApiResponse(responseCode = "404",
            description = "The Host header has no sub-label (apex), the first label is reserved "
                + "or confusable-of-reserved, or no public profile exists for the username."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error during the resolve. Check server logs.")
    })
    @GetMapping
    public Mono<VanityProfileDto> resolveByHost(
            @RequestHeader(value = "Host", required = false) String host) {
        // Extract the first DNS label from the Host header — null when the host is
        // absent, blank, or has fewer than 3 labels (bare apex).
        String label = firstLabel(host);
        if (label == null) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "no vanity username in host: " + host));
        }
        return resolveLabel(label);
    }

    // -------------------------------------------------------------------------
    // Shared resolve (READ-LAYER enforcement)
    // -------------------------------------------------------------------------

    /**
     * Shared resolve with READ-LAYER defence:
     * <ol>
     *   <li>Reject an EXACT reserved label (fast O(1) set check, no DB).</li>
     *   <li>Reject a CONFUSABLE-of-reserved label via the precomputed skeleton
     *       set (O(1), no DB). Belt-and-braces against write-layer races or ICU
     *       fold shifts that could have let a {@code profile-4dmin} fragment slip
     *       through.</li>
     *   <li>Resolve-or-404: delegate to {@link VanityService#resolve} which applies
     *       the public+enabled+closed+owner-not-banned invariants in the query and
     *       in code.</li>
     * </ol>
     *
     * @param label the DNS label (lowercased) to resolve — may be null
     * @return a {@code Mono<VanityProfileDto>} emitting the descriptor, or
     *         {@code Mono.error} with 404 when any gate rejects
     */
    private Mono<VanityProfileDto> resolveLabel(String label) {
        // Gate 1: exact reserved label (e.g. "api", "matrix").
        if (label != null && RESERVED_LABELS.contains(label.toLowerCase())) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "reserved subdomain, not a vanity username: " + label));
        }
        // Gate 2: confusable of a reserved label (e.g. "4dmin" → skeleton "admin").
        // This is defence-in-depth: even if a profile-4dmin fragment minted through a
        // race or ICU shift, the vanity host still 404s here without a DB lookup.
        if (label != null && skeletons.isReservedSkeleton(label)) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "confusable of a reserved subdomain, not a vanity username: " + label));
        }
        // Gate 3: DB resolve — VanityService enforces public+enabled+closed+owner-not-banned.
        return vanity.resolve(label)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "no public profile for: " + label)));
    }

    // -------------------------------------------------------------------------
    // Host-header parsing
    // -------------------------------------------------------------------------

    /**
     * Extracts the first DNS label (the vanity username) from a {@code Host} header
     * value. Strips a trailing {@code :port}, lower-cases, and requires at least
     * three labels ({@code <user>.<domain>.<tld>}) — so the bare apex
     * ({@code snapdragon.systems} — exactly 2 labels) returns {@code null} rather
     * than the label {@code "snapdragon"}.
     *
     * <p>Package-private and static for direct unit testing.
     *
     * @param host the raw {@code Host} header value, e.g.
     *             {@code "alice.snapdragon.systems:8080"}; may be null or blank
     * @return the first DNS label in lower-case (e.g. {@code "alice"}), or
     *         {@code null} when the host is absent, blank, or has fewer than
     *         3 labels
     */
    static String firstLabel(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }
        String h = host.trim().toLowerCase();
        // Strip optional port suffix (e.g. ":8080").
        int colon = h.indexOf(':');
        if (colon >= 0) {
            h = h.substring(0, colon);
        }
        String[] labels = h.split("\\.");
        // A vanity host has at least 3 labels: <user>.<domain>.<tld>. With exactly
        // 2 labels (the apex domain.tld) there is no username component → null.
        if (labels.length < 3 || labels[0].isBlank()) {
            return null;
        }
        return labels[0];
    }
}
