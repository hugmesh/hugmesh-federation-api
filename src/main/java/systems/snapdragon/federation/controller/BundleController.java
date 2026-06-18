package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
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
import systems.snapdragon.federation.security.DomainRegistry;
import systems.snapdragon.federation.security.DomainScope;
import systems.snapdragon.federation.service.BundleService;
import systems.snapdragon.federation.web.ValidationPatterns;

import java.util.Map;

/**
 * Bundle storage endpoints for per-user federated modules. Lifted from the games
 * AssetController's content-hash-addressed serving:
 *
 * <ul>
 *   <li>PUT a module bundle (owner-authenticated).</li>
 *   <li>LIST bundles by owner or by slug.</li>
 *   <li>FETCH a bundle file by content-hash + relative path — the
 *       {@code snapdragon-remote-fragment} pods SYNC this and serve it as static
 *       files (sync-and-serve-static).</li>
 * </ul>
 *
 * <p>Write is owner-or-admin (the owner is the JWT subject). The METADATA reads
 * (LIST-by-slug + by-content-hash) are DOMAIN-scoped + OWNER-scoped and return a
 * public-safe view ({@code UserModuleView}, no {@code versionDir}/{@code ownerUserId})
 * — a per-domain caller never sees another brand's (or a non-admin, another owner's)
 * bundle metadata; SUPERADMIN sees all. The content-hash byte FETCH stays
 * any-authenticated (the remote-fragment pods present a service token; a content hash
 * is a capability and the bytes are identical to whoever holds it). Content-type is
 * resolved from the extension, like the games AssetController media-type table.
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

    @Operation(summary = "List my bundles (owner = JWT subject).")
    @GetMapping("/mine")
    public Flux<UserModule> mine(@AuthenticationPrincipal Jwt jwt) {
        return bundles.listForOwner(jwt.getSubject());
    }

    @Operation(
        summary = "List bundle versions for a slug (DOMAIN + owner scoped; public-safe view).",
        description = """
            Returns the public-safe view (slug, contentHash, entryFile, manifestJson,
            visibility, timestamps — NO versionDir/ownerUserId) of the slug's bundle
            versions the caller may see: a per-domain NON-admin sees ONLY their OWN
            bundles in their brand; a per-domain ADMIN sees their brand's; SUPERADMIN
            sees all. A slug in another brand returns EMPTY — never cross-tenant
            metadata.
            """)
    @GetMapping("/slug/{slug}")
    public Flux<UserModuleView> bySlug(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.SLUG, message = "invalid slug") String slug) {
        DomainScope scope = DomainScope.resolve(jwt, domains);
        return adminMono().flatMapMany(admin ->
                bundles.listForSlug(slug, scope, jwt.getSubject(), admin));
    }

    @Operation(
        summary = "Bundle metadata by content-hash (DOMAIN + owner scoped; public-safe view).",
        description = """
            Returns the public-safe view (NO versionDir/ownerUserId) of the bundle for a
            content hash the caller may resolve: a per-domain NON-admin only resolves a
            hash for a bundle they OWN in their brand; a per-domain ADMIN, their brand's;
            SUPERADMIN, any. A hash in another brand (or, for a non-admin, another owner)
            is 404 — closing the cross-tenant metadata IDOR + content-hash->bytes pivot.
            """)
    @GetMapping("/{contentHash}")
    public Mono<UserModuleView> byHash(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @Pattern(regexp = ValidationPatterns.CONTENT_HASH,
                    message = "contentHash must be 64 lower-hex chars") String contentHash) {
        DomainScope scope = DomainScope.resolve(jwt, domains);
        return adminMono().flatMap(admin ->
                bundles.byContentHash(contentHash, scope, jwt.getSubject(), admin));
    }

    @Operation(
        summary = "PUT a module bundle (single entry file).",
        description = """
            Stages the request body, SHA-256-hashes it into a content-addressed
            version, installs it via the BundleStorage strategy, records a
            user_modules row, and supersedes the CALLER'S OWN prior active version
            for the slug. Owner-scoped: if the slug already has an active version
            owned by ANOTHER user, a non-admin PUT is rejected (409) and the
            victim's row is left untouched; ADMIN may supersede regardless of owner.
            The full multi-file zip pipeline is deferred (see README).
            """)
    @PutMapping(value = "/{slug}", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Mono<UserModule> put(@AuthenticationPrincipal Jwt jwt,
                                @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                                        message = "invalid slug") String slug,
                                @RequestParam(value = "entryFile", required = false)
                                @Size(max = 512, message = "entryFile must be at most 512 chars") String entryFile,
                                @RequestParam(value = "visibility", required = false)
                                @Pattern(regexp = ValidationPatterns.VISIBILITY,
                                        message = "visibility must be public|internal") String visibility,
                                @RequestParam(value = "manifest", required = false) String manifestJson,
                                @RequestBody Flux<DataBuffer> body) {
        DomainScope scope = DomainScope.resolve(jwt, domains);
        return adminMono()
                .flatMap(admin -> bundles.put(jwt.getSubject(), slug, entryFile,
                        visibility, manifestJson, admin, scope, body));
    }

    @Operation(
        summary = "READ my card's current body by slug (owner = JWT subject).",
        description = """
            Returns the entry-file bytes of the CALLER'S OWN active (non-superseded)
            bundle for the slug — the read-my-card-body the user-bff proxies so the
            WYSIWYG editor can pre-fill for Edit. Owner-scoped: a normal user only
            ever reads their own card (a non-owner gets 404, never another user's
            bytes); ADMIN may read the slug's active row regardless of owner. 404 if
            the caller has no active bundle for the slug.
            """)
    @GetMapping("/slug/{slug}/body")
    public Mono<ResponseEntity<Resource>> readBody(@AuthenticationPrincipal Jwt jwt,
                                                   @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                                                           message = "invalid slug") String slug) {
        return adminMono()
                .flatMap(admin -> bundles.readOwnBody(jwt.getSubject(), slug, admin))
                .map(res -> ResponseEntity.ok().contentType(mediaTypeFor(slug)).body(res));
    }

    @Operation(
        summary = "DELETE my current bundle for a slug (owner = JWT subject).",
        description = """
            Deletes the CALLER'S OWN active (non-superseded) bundle for the slug:
            removes the content-addressed version from storage and marks the
            user_modules row superseded (mirrors PUT supersession), so the slug has
            no active version afterwards and history stays queryable. Owner-scoped: a
            normal user deletes ONLY their own card (a non-owner gets 404, never a
            cross-tenant delete); ADMIN may delete the slug's active row regardless
            of owner. 404 if the caller has no active bundle for the slug.
            """)
    @DeleteMapping("/{slug}")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public Mono<Void> delete(@AuthenticationPrincipal Jwt jwt,
                             @PathVariable @Pattern(regexp = ValidationPatterns.SLUG,
                                     message = "invalid slug") String slug) {
        return adminMono()
                .flatMap(admin -> bundles.deleteForOwner(jwt.getSubject(), slug, admin));
    }

    /** True when the current caller holds {@code ROLE_ADMIN} (Casdoor admin override). */
    private static Mono<Boolean> adminMono() {
        return org.springframework.security.core.context.ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                        .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())))
                .defaultIfEmpty(false);
    }

    @Operation(
        summary = "FETCH a bundle file by content-hash (remote-fragment SYNC read).",
        description = """
            Streams a single file from a content-addressed bundle. The
            snapdragon-remote-fragment pods call this to sync a bundle and serve
            it as static files. `{*path}` captures the rest of the URL as the
            relative path inside the bundle.
            """)
    @GetMapping("/{contentHash}/files/{*path}")
    public Mono<ResponseEntity<Resource>> fetch(@PathVariable @Pattern(regexp = ValidationPatterns.CONTENT_HASH,
                                                        message = "contentHash must be 64 lower-hex chars") String contentHash,
                                                @PathVariable String path) {
        String rel = path.startsWith("/") ? path.substring(1) : path;
        return bundles.fetch(contentHash, rel)
                .map(res -> ResponseEntity.ok().contentType(mediaTypeFor(rel)).body(res));
    }

    private static MediaType mediaTypeFor(String name) {
        String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase() : "";
        return MEDIA_TYPES.getOrDefault(ext, MediaType.APPLICATION_OCTET_STREAM);
    }
}
