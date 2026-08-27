package net.hugmesh.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.model.FederationModule;
import net.hugmesh.federation.model.VanityProfileDto;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.federation.service.UsernameSkeletonService;
import net.hugmesh.federation.service.VanityPublishService;
import net.hugmesh.federation.service.VanityService;
import net.hugmesh.federation.web.ValidationPatterns;

import static net.hugmesh.federation.controller.ReservedNames.RESERVED_LABELS;

/**
 * Vanity-subdomain resolve — the PUBLIC read path behind
 * {@code <username>.hugmesh.net}.
 *
 * <p>Exposes two shapes of the same resolve:
 * <ul>
 *   <li>{@code GET /api/federation/vanity/{username}} — explicit username in the
 *       path variable; used by tooling and by the fe-gateway when it extracts the
 *       first DNS label and rewrites the path.</li>
 *   <li>{@code GET /api/federation/vanity} with a {@code Host:} header — the API
 *       extracts the username itself from the FIRST DNS LABEL of the host
 *       ({@code alice.hugmesh.net → alice}), letting the gateway forward
 *       the vanity request verbatim (preserving Host) with NO path rewrite.</li>
 * </ul>
 *
 * <h2>Security gating</h2>
 * <p>{@code GET /api/federation/vanity/**} is {@code permitAll} (see
 * {@link net.hugmesh.federation.config.SecurityConfig}, declared BEFORE the
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
 * BEFORE the {@code *.hugmesh.net} wildcard, so they never arrive here.
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
 * @see net.hugmesh.federation.config.SecurityConfig
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

    /**
     * The owner-scoped self-publish/unpublish write service — backs
     * {@code PUT}/{@code DELETE /api/federation/vanity/{username}} (see the
     * <em>Vanity PUBLISH path</em> section of the README). Distinct from
     * {@link #vanity} (the public READ service) so the public GET surface's
     * security reasoning stays untouched by the authenticated write path.
     */
    private final VanityPublishService publish;

    /** Resolves the caller's tenant scope from the validated JWT issuer, mirroring
     *  every other authenticated write controller in this service. */
    private final DomainRegistry domains;

    public VanityController(VanityService vanity, UsernameSkeletonService skeletons,
                            VanityPublishService publish, DomainRegistry domains) {
        this.vanity = vanity;
        this.skeletons = skeletons;
        this.publish = publish;
        this.domains = domains;
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
            <code>Host</code> header (<code>alice.hugmesh.net → alice</code>)
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
    // Owner-scoped self-publish / unpublish (AUTHENTICATED write path)
    // -------------------------------------------------------------------------

    /**
     * Optional request body for {@link #publish}. {@code displayName} is the only
     * client-suppliable field — {@code remoteEntryUrl} / {@code contentHash} are
     * ALWAYS derived server-side from the caller's own active bundle (see
     * {@link VanityPublishService}), never accepted from the request, so a caller
     * can never register a fragment pointing at bytes they did not upload.
     */
    public record PublishRequest(
            @Size(max = 1024, message = "displayName must be at most 1024 chars") String displayName) {
    }

    @Operation(
        summary = "Publish (or refresh) the CALLER'S OWN vanity profile fragment.",
        description = """
            Owner-scoped write: upserts the caller's <code>profile-&lt;username&gt;</code>
            <code>federation_modules</code> row (<code>visibility=public,
            enabled=true</code>) FROM their own already-uploaded
            <code>user_modules</code> bundle for the same slug
            (<code>PUT /api/federation/bundles/profile-&lt;username&gt;</code> —
            upload the bundle bytes FIRST). <code>remoteEntryUrl</code> and
            <code>contentHash</code> are always derived from that bundle server-side.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller</th><th>Result</th></tr>
              <tr><td>Authenticated caller, <code>username</code> == own vanity label
                  (<code>preferred_username</code>)</td>
                  <td>Publishes/refreshes own profile fragment</td></tr>
              <tr><td>ROLE_ADMIN / ROLE_SUPERADMIN</td>
                  <td>May publish on behalf of any username</td></tr>
              <tr><td>Any other authenticated caller</td><td>403</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Profile fragment published/refreshed and returned."),
        @ApiResponse(responseCode = "400",
            description = "username fails the DNS-label-token pattern, is a reserved platform "
                + "name, or is confusable with one."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "username does not match the caller's own vanity label (the token's "
                + "preferred_username claim) and the caller does not hold ROLE_ADMIN or "
                + "ROLE_SUPERADMIN. Also returned when the token carries no label claim at all "
                + "(fail-closed — the label is never derived from the JWT subject)."),
        @ApiResponse(responseCode = "404",
            description = "No active bundle uploaded yet for profile-<username> — "
                + "PUT /api/federation/bundles/profile-<username> first."),
        @ApiResponse(responseCode = "409",
            description = "The existing profile-<username> fragment was administratively "
                + "unpublished (admin kill-switch, enabled=false with visibility still public) — "
                + "only an admin can restore it, via POST "
                + "/api/federation/overrides/profile-<username>/rearm."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error during the publish. Check server logs.")
    })
    @PutMapping("/{username}")
    public Mono<FederationModule> publish(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String username,
            @RequestBody(required = false) PublishRequest body) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        String displayName = body == null ? null : body.displayName();
        // TWO axes, deliberately both passed: the SUBJECT scopes the user_modules read
        // (owner_user_id is the Casdoor UUID BundleController stamped); the LABEL is what
        // the owner guard compares to `username`. See VanityPublishService's class javadoc.
        return adminMono().flatMap(admin ->
                publish.publish(jwt.getSubject(), vanityLabelOf(jwt), admin, username,
                        displayName, scope));
    }

    @Operation(
        summary = "Unpublish the CALLER'S OWN vanity profile fragment.",
        description = """
            Owner-scoped write: flips the caller's <code>profile-&lt;username&gt;</code>
            fragment (if any) to <code>visibility=internal, enabled=false</code> — the
            profile immediately stops resolving at the vanity host. The row is never
            deleted (history + the confusable-skeleton grant survive for a future
            republish). Idempotent: unpublishing a profile that was never published
            is a no-op, not an error.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller</th><th>Result</th></tr>
              <tr><td>Authenticated caller, <code>username</code> == own vanity label
                  (<code>preferred_username</code>)</td>
                  <td>Unpublishes own profile fragment</td></tr>
              <tr><td>ROLE_ADMIN / ROLE_SUPERADMIN</td>
                  <td>May unpublish on behalf of any username</td></tr>
              <tr><td>Any other authenticated caller</td><td>403</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "204",
            description = "Profile fragment unpublished (or was never published); no body returned."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "403",
            description = "username does not match the caller's own vanity label (the token's "
                + "preferred_username claim) and the caller does not hold ROLE_ADMIN or "
                + "ROLE_SUPERADMIN. Also returned when the token carries no label claim at all "
                + "(fail-closed — the label is never derived from the JWT subject)."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error during the unpublish. Check server logs.")
    })
    @DeleteMapping("/{username}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> unpublish(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.USERNAME,
                    message = "username must be a DNS-label token") String username) {
        return adminMono().flatMap(admin ->
                publish.unpublish(jwt.getSubject(), vanityLabelOf(jwt), admin, username));
    }

    /**
     * The caller's own vanity LABEL (DNS label) as carried on the token — the axis the
     * owner guard on this controller's write surface compares to the {@code username}
     * path segment.
     *
     * <p>Deliberately mirrors user-bff-api's {@code ProfileController.usernameOf} — the
     * OTHER end of this call, which derives the path segment the same way — with ONE
     * intentional divergence: <b>there is no fallback to {@code jwt.getSubject()}</b>.
     * On this platform the subject is a Casdoor UUID (or a bff_-session
     * {@code provider:handle} composite), never a DNS label, so a subject fallback could
     * only ever produce a bogus comparison; worse, a principal whose subject string
     * happened to equal a victim's label would be handed ownership of that label. A
     * token with neither claim therefore yields {@code null}, which the service's owner
     * guard turns into a 403.
     *
     * @param jwt the validated access token
     * @return the {@code preferred_username} claim, else {@code name}, else {@code null}
     */
    static String vanityLabelOf(Jwt jwt) {
        if (jwt == null) {
            return null;
        }
        String preferred = jwt.getClaimAsString("preferred_username");
        if (preferred != null && !preferred.isBlank()) {
            return preferred;
        }
        String name = jwt.getClaimAsString("name");
        if (name != null && !name.isBlank()) {
            return name;
        }
        return null;
    }

    /**
     * Whether the current caller holds {@code ROLE_ADMIN} or {@code ROLE_SUPERADMIN}
     * (mirrors {@code BundleController#adminMono}, duplicated per-controller by this
     * codebase's existing convention). Reads the reactive security context so it is
     * safe to call on the WebFlux event loop without blocking.
     */
    private static Mono<Boolean> adminMono() {
        return org.springframework.security.core.context.ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())
                                || "ROLE_SUPERADMIN".equals(a.getAuthority())))
                .defaultIfEmpty(false);
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
     * ({@code hugmesh.net} — exactly 2 labels) returns {@code null} rather
     * than the label {@code "hugmesh"}.
     *
     * <p>Package-private and static for direct unit testing.
     *
     * @param host the raw {@code Host} header value, e.g.
     *             {@code "alice.hugmesh.net:8080"}; may be null or blank
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
