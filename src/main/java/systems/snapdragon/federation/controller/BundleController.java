package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.core.io.Resource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.model.UserModuleView;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.commons.security.PrincipalDomain;
import systems.snapdragon.federation.service.BundleService;
import systems.snapdragon.federation.web.ValidationPatterns;

import java.util.Map;

/**
 * Per-user federated-module bundle storage: PUT / LIST / FETCH / DELETE.
 *
 * <p>Lifted from the games {@code AssetController}'s content-hash-addressed serving:
 * each uploaded bundle is SHA-256 hashed into a content-addressed location so the
 * {@code snapdragon-remote-fragment} pods can SYNC it by hash and serve it as static
 * files (the sync-and-serve-static pattern).
 *
 * <h2>Security gating</h2>
 * <p>All paths under {@code /api/federation/bundles/**} require an authenticated
 * Casdoor JWT (see {@link systems.snapdragon.federation.config.SecurityConfig}).
 * Within that authenticated perimeter the access model differs by endpoint:
 *
 * <ul>
 *   <li><b>Write (PUT) + Read-own-body (GET /slug/{slug}/body) + Delete</b> —
 *       owner-or-admin: the authenticated caller must be the {@code ownerUserId}
 *       (JWT subject) of the active bundle, OR hold {@code ROLE_ADMIN}. A non-owner
 *       receives 404 (cross-tenant attempt is indistinguishable from not-found).
 *       The admin override is DOMAIN-scoped: a per-domain {@code ROLE_ADMIN} reaches
 *       only their OWN brand's active row (a foreign brand's slug 404s), and only a
 *       {@code ROLE_SUPERADMIN} reaches any brand — so a brand admin can neither read
 *       nor delete nor supersede another brand's card.</li>
 *   <li><b>Metadata reads (GET /mine, GET /slug/{slug}, GET /{contentHash})</b> —
 *       DOMAIN-scoped + OWNER-scoped, projected to the public-safe
 *       {@link UserModuleView} (no {@code versionDir} / {@code ownerUserId}). A
 *       per-domain non-admin sees ONLY their own bundles in their brand; a per-domain
 *       ADMIN sees their brand's; SUPERADMIN sees all. A slug or hash in another
 *       brand is invisible (never a 403, always 404 or empty).</li>
 *   <li><b>Content-hash byte FETCH (GET /{contentHash}/files/{*path})</b> —
 *       any-authenticated. The remote-fragment pods present a service token; a
 *       content hash is itself a capability (a collision-resistant 64 hex chars) and
 *       the bytes are identical to whoever holds it.</li>
 * </ul>
 *
 * @see BundleService
 * @see systems.snapdragon.federation.config.SecurityConfig
 */
@Tag(name = "Bundles", description = "Per-user federated-module bundle storage + content-hash sync.")
@RestController
@RequestMapping("/api/federation/bundles")
@Validated
public class BundleController {

    private final BundleService bundles;
    private final DomainRegistry domains;

    public BundleController(BundleService bundles, DomainRegistry domains) {
        this.bundles = bundles;
        this.domains = domains;
    }

    /**
     * Extension → {@link MediaType} map used to resolve the {@code Content-Type}
     * of served bundle files. Matches the games {@code AssetController} media-type
     * table. Unknown extensions fall back to {@code application/octet-stream}.
     */
    private static final Map<String, MediaType> MEDIA_TYPES = Map.ofEntries(
            Map.entry("html", MediaType.TEXT_HTML),
            Map.entry("js",   MediaType.valueOf("application/javascript")),
            Map.entry("mjs",  MediaType.valueOf("application/javascript")),
            Map.entry("css",  MediaType.valueOf("text/css")),
            Map.entry("json", MediaType.APPLICATION_JSON),
            Map.entry("png",  MediaType.IMAGE_PNG),
            Map.entry("svg",  MediaType.valueOf("image/svg+xml")),
            Map.entry("wasm", MediaType.valueOf("application/wasm")),
            Map.entry("map",  MediaType.APPLICATION_JSON)
    );

    // -------------------------------------------------------------------------
    // Owner-scoped reads
    // -------------------------------------------------------------------------

    @Operation(
        summary = "List my bundles (owner = JWT subject).",
        description = """
            Returns every <code>user_modules</code> row owned by the authenticated
            caller (identified by the JWT subject), ordered newest-first. Returns
            the <em>full</em> entity (including <code>versionDir</code> /
            <code>ownerUserId</code>) because the caller is always the owner.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Rows returned</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD / ROLE_ADMIN</td>
                  <td>Own bundles only (JWT subject)</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Own bundles only (JWT subject) — use
                      <code>GET /slug/{slug}</code> for cross-brand views</td></tr>
            </table>
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "List returned — empty array when the caller has no bundles."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying user_modules. Check server logs.")
    })
    @GetMapping("/mine")
    public Flux<UserModule> mine(@AuthenticationPrincipal Jwt jwt) {
        // Owner filter is the JWT subject — never a request param (spoofable).
        return bundles.listForOwner(jwt.getSubject());
    }

    // -------------------------------------------------------------------------
    // Domain-scoped metadata reads (public-safe view)
    // -------------------------------------------------------------------------

    @Operation(
        summary = "List bundle versions for a slug (DOMAIN + owner scoped; public-safe view).",
        description = """
            Returns the public-safe view
            (<code>slug, contentHash, entryFile, manifestJson, visibility,
            timestamps</code> — NO <code>versionDir</code>/<code>ownerUserId</code>)
            of the slug's bundle versions the caller may see.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Scope</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD</td>
                  <td>Own bundles for slug, own brand only</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Any owner for slug, own brand only</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Any owner, any brand</td></tr>
            </table>

            A slug that belongs to another brand is returned <em>empty</em> —
            never cross-tenant metadata leakage.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "List returned — empty array when no visible bundles exist for the slug."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while querying user_modules. Check server logs.")
    })
    @GetMapping("/slug/{slug}")
    public Flux<UserModuleView> bySlug(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        // Resolve admin flag from the reactive security context, then delegate to the
        // domain-scoped service with all three parameters: slug, brand scope, and
        // owner (JWT subject for non-admin callers).
        return adminMono().flatMapMany(admin ->
                bundles.listForSlug(slug, scope, jwt.getSubject(), admin));
    }

    @Operation(
        summary = "Bundle metadata by content-hash (DOMAIN + owner scoped; public-safe view).",
        description = """
            Returns the public-safe view (NO <code>versionDir</code>/<code>ownerUserId</code>)
            of the bundle for a content hash the caller may resolve.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Scope</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD</td>
                  <td>Own bundle matching hash, own brand only</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Any owner's bundle matching hash, own brand only</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Any bundle matching hash, any brand</td></tr>
            </table>

            A hash in another brand (or, for a non-admin, another owner) is 404 —
            closing the cross-tenant metadata IDOR + the content-hash→bytes pivot.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Bundle metadata returned as a public-safe UserModuleView."),
        @ApiResponse(responseCode = "400",
            description = "contentHash path variable is not a valid 64 lower-hex character string."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "404",
            description = "No bundle for that hash visible to this caller — either it does not "
                + "exist, belongs to another brand, or (for a non-admin) belongs to another owner."),
        @ApiResponse(responseCode = "500",
            description = "Postgres error while resolving the bundle. Check server logs.")
    })
    @GetMapping("/{contentHash}")
    public Mono<UserModuleView> byHash(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.CONTENT_HASH,
                    message = "contentHash must be 64 lower-hex chars") String contentHash) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        return adminMono().flatMap(admin ->
                bundles.byContentHash(contentHash, scope, jwt.getSubject(), admin));
    }

    // -------------------------------------------------------------------------
    // Write
    // -------------------------------------------------------------------------

    @Operation(
        summary = "PUT a module bundle (single entry file).",
        description = """
            Stages the request body, SHA-256-hashes it into a content-addressed
            version, installs it via the <code>BundleStorage</code> strategy,
            records a <code>user_modules</code> row, and supersedes the CALLER'S OWN
            prior active version for the slug.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Allowed action</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD</td>
                  <td>PUT own bundle for slug; 409 if slug's active row is owned by
                      another user</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>PUT and supersede the slug's active row for any owner in OWN
                      brand; a foreign brand's active card is never displaced</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>PUT and supersede the slug's active row regardless of owner or brand</td></tr>
            </table>

            <p>If the slug already has an active version owned by ANOTHER user, a
            non-admin PUT is rejected with 409 BEFORE any supersede / insert runs
            (fail-closed). The victim's row is left untouched. The full multi-file zip
            pipeline is deferred (see README).
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Bundle accepted and installed; returns the new user_modules row."),
        @ApiResponse(responseCode = "400",
            description = "slug / entryFile / visibility parameter validation failure, or the "
                + "entryFile path escapes the bundle directory (traversal reject)."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "409",
            description = "The slug already has an active bundle owned by a different user "
                + "and the caller does not hold ROLE_ADMIN."),
        @ApiResponse(responseCode = "413",
            description = "The uploaded body exceeds the configured app.bundles.max-bytes "
                + "ceiling (default 256 MiB); the partial staged file is discarded."),
        @ApiResponse(responseCode = "500",
            description = "Filesystem staging, hashing, or Postgres error. Check server logs.")
    })
    @PutMapping(value = "/{slug}", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Mono<UserModule> put(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                    message = "invalid slug") String slug,
            @RequestParam(value = "entryFile", required = false)
            @Size(max = 512, message = "entryFile must be at most 512 chars") String entryFile,
            @RequestParam(value = "visibility", required = false)
            @Pattern(regexp = ValidationPatterns.VISIBILITY,
                    message = "visibility must be public|internal") String visibility,
            @RequestParam(value = "manifest", required = false) String manifestJson,
            @RequestBody Flux<DataBuffer> body) {
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        // Domain is always stamped from the validated JWT scope — never from the
        // request body — so a caller cannot plant a bundle in another brand's domain.
        return adminMono()
                .flatMap(admin -> bundles.put(jwt.getSubject(), slug, entryFile,
                        visibility, manifestJson, admin, scope, body));
    }

    // -------------------------------------------------------------------------
    // Owner-scoped read-own-body / delete
    // -------------------------------------------------------------------------

    @Operation(
        summary = "READ my card's current body by slug (owner = JWT subject).",
        description = """
            Returns the entry-file bytes of the CALLER'S OWN active (non-superseded)
            bundle for the slug — the read-my-card-body the user-bff proxies so the
            WYSIWYG editor can pre-fill for Edit.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Allowed action</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD</td>
                  <td>Read own active bundle body; 404 if not the owner</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Read the slug's active bundle body for any owner in OWN brand;
                      404 for another brand's slug</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Read the slug's active bundle body regardless of owner or brand</td></tr>
            </table>

            <p>A non-owner gets 404 — never another user's bytes; a per-domain admin
            reaching for another brand's slug also gets 404 (never cross-tenant bytes).
            Content-Type is resolved from the bundle's entry-file extension.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "Entry-file bytes returned; Content-Type resolved from the file extension."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "404",
            description = "No active bundle for the slug owned by this caller, or the entry file "
                + "is absent from storage."),
        @ApiResponse(responseCode = "500",
            description = "Filesystem read or Postgres error. Check server logs.")
    })
    @GetMapping("/slug/{slug}/body")
    public Mono<ResponseEntity<Resource>> readBody(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                    message = "invalid slug") String slug) {
        // Brand scope from the validated JWT pins a per-domain admin's read to their own
        // brand, so an admin can never exfiltrate another brand's card body.
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        // Resolve Content-Type from the slug's extension so the caller knows what kind
        // of bundle body (JS, HTML, JSON, etc.) they are receiving.
        return adminMono()
                .flatMap(admin -> bundles.readOwnBody(jwt.getSubject(), slug, admin, scope))
                .map(res -> ResponseEntity.ok().contentType(mediaTypeFor(slug)).body(res));
    }

    @Operation(
        summary = "DELETE my current bundle for a slug (owner = JWT subject).",
        description = """
            Deletes the CALLER'S OWN active (non-superseded) bundle for the slug:
            removes the content-addressed version from storage and marks the
            <code>user_modules</code> row superseded, so the slug has no active
            version afterwards but history stays queryable.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Allowed action</th></tr>
              <tr><td>ROLE_USER / ROLE_MOD</td>
                  <td>Delete own active bundle; 404 if not the owner</td></tr>
              <tr><td>ROLE_ADMIN</td>
                  <td>Delete the slug's active bundle for any owner in OWN brand;
                      404 for another brand's slug</td></tr>
              <tr><td>ROLE_SUPERADMIN</td>
                  <td>Delete the slug's active bundle regardless of owner or brand</td></tr>
            </table>

            <p>A non-owner gets 404 — never a cross-tenant delete; a per-domain admin
            reaching for another brand's slug also gets 404 (never a cross-tenant delete).
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "204",
            description = "Bundle deleted and row superseded; no body returned."),
        @ApiResponse(responseCode = "400",
            description = "slug path variable fails the DNS-label-style pattern constraint."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "404",
            description = "No active bundle for the slug owned by this caller."),
        @ApiResponse(responseCode = "500",
            description = "Filesystem or Postgres error. Check server logs.")
    })
    @DeleteMapping("/{slug}")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public Mono<Void> delete(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                    message = "invalid slug") String slug) {
        // Brand scope from the validated JWT pins a per-domain admin's delete to their own
        // brand, so an admin can never destroy another brand's card.
        PrincipalDomain scope = PrincipalDomain.resolve(jwt, domains);
        return adminMono()
                .flatMap(admin -> bundles.deleteForOwner(jwt.getSubject(), slug, admin, scope));
    }

    // -------------------------------------------------------------------------
    // Remote-fragment SYNC read (any-authenticated)
    // -------------------------------------------------------------------------

    @Operation(
        summary = "FETCH a bundle file by content-hash (remote-fragment SYNC read).",
        description = """
            Streams a single file from a content-addressed bundle. The
            <code>snapdragon-remote-fragment</code> pods call this to sync a bundle
            and serve it as static files. <code>{*path}</code> captures the rest of
            the URL as the relative path inside the bundle directory.

            <h4>Caller-role access matrix</h4>
            <table>
              <tr><th>Caller role</th><th>Result</th></tr>
              <tr><td>Any authenticated caller (user / mod / admin / service token)</td>
                  <td>File bytes returned if the hash and path exist</td></tr>
            </table>

            <p>A content hash is itself a 256-bit capability; the bytes are identical
            to whoever holds it. This endpoint intentionally does NOT apply
            owner/domain scoping — see the class-level Javadoc for the rationale.
            Content-Type is resolved from the file extension.
            """)
    @ApiResponses({
        @ApiResponse(responseCode = "200",
            description = "File bytes returned; Content-Type resolved from the path extension."),
        @ApiResponse(responseCode = "400",
            description = "contentHash is not a valid 64 lower-hex character string."),
        @ApiResponse(responseCode = "401",
            description = "Missing, expired, or invalid Casdoor JWT."),
        @ApiResponse(responseCode = "404",
            description = "No bundle for that content-hash, or the relative path does not "
                + "exist inside the bundle."),
        @ApiResponse(responseCode = "500",
            description = "Filesystem read or Postgres error. Check server logs.")
    })
    @GetMapping("/{contentHash}/files/{*path}")
    public Mono<ResponseEntity<Resource>> fetch(
            @PathVariable @Pattern(regexp = ValidationPatterns.CONTENT_HASH,
                    message = "contentHash must be 64 lower-hex chars") String contentHash,
            @PathVariable String path) {
        // Strip the leading '/' that the path-variable capture includes when the
        // first segment starts with '/'.
        String rel = path.startsWith("/") ? path.substring(1) : path;
        return bundles.fetch(contentHash, rel)
                .map(res -> ResponseEntity.ok().contentType(mediaTypeFor(rel)).body(res));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Returns {@code true} when the current caller holds {@code ROLE_ADMIN}
     * (Casdoor admin override). Reads the reactive security context so it is
     * safe to call on the WebFlux event loop without blocking.
     *
     * @return a {@code Mono<Boolean>} emitting {@code true} iff the caller is admin
     */
    private static Mono<Boolean> adminMono() {
        return org.springframework.security.core.context.ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())))
                .defaultIfEmpty(false);
    }

    /**
     * Resolves the {@link MediaType} for a file name (or relative path) from its
     * extension. Falls back to {@code application/octet-stream} for unknown extensions.
     *
     * @param name the file name or relative path, e.g. {@code "remoteEntry.json"}
     * @return the resolved {@link MediaType}
     */
    private static MediaType mediaTypeFor(String name) {
        String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase() : "";
        return MEDIA_TYPES.getOrDefault(ext, MediaType.APPLICATION_OCTET_STREAM);
    }
}
