package systems.snapdragon.federation.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.io.Resource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.service.BundleService;

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
 * <p>Write is owner-or-admin (the owner is the JWT subject); fetch is
 * authenticated (the remote-fragment pods present a service token). Content-type
 * is resolved from the extension, like the games AssetController media-type table.
 */
@Tag(name = "Bundles", description = "Per-user federated-module bundle storage + content-hash sync.")
@RestController
@RequestMapping("/api/federation/bundles")
public class BundleController {

    private final BundleService bundles;

    public BundleController(BundleService bundles) {
        this.bundles = bundles;
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

    @Operation(summary = "List bundle versions for a slug.")
    @GetMapping("/slug/{slug}")
    public Flux<UserModule> bySlug(@PathVariable String slug) {
        return bundles.listForSlug(slug);
    }

    @Operation(summary = "Bundle metadata by content-hash.")
    @GetMapping("/{contentHash}")
    public Mono<UserModule> byHash(@PathVariable String contentHash) {
        return bundles.byContentHash(contentHash);
    }

    @Operation(
        summary = "PUT a module bundle (single entry file).",
        description = """
            Stages the request body, SHA-256-hashes it into a content-addressed
            version, installs it via the BundleStorage strategy, records a
            user_modules row, and supersedes the prior active version for the slug.
            The full multi-file zip pipeline is deferred (see README).
            """)
    @PutMapping(value = "/{slug}", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Mono<UserModule> put(@AuthenticationPrincipal Jwt jwt,
                                @PathVariable String slug,
                                @RequestParam(value = "entryFile", required = false) String entryFile,
                                @RequestParam(value = "visibility", required = false) String visibility,
                                @RequestParam(value = "manifest", required = false) String manifestJson,
                                @RequestBody Flux<DataBuffer> body) {
        return bundles.put(jwt.getSubject(), slug, entryFile, visibility, manifestJson, body);
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
    public Mono<ResponseEntity<Resource>> fetch(@PathVariable String contentHash,
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
