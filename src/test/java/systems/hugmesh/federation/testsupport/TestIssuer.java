package systems.hugmesh.federation.testsupport;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REUSABLE multi-issuer test fixture — the cornerstone of the copyable multi-issuer
 * security-slice pattern (see {@code docs/testing/MULTI-ISSUER-SLICE.md}). COPIED
 * VERBATIM (package adjusted) from the canonical
 * {@code systems.hugmesh.gateway.testsupport.TestIssuer}.
 *
 * <p>Each {@code TestIssuer} stands up a tiny in-process HTTP server (JDK
 * {@link HttpServer}, bound to {@code 127.0.0.1}) that serves exactly what Spring
 * Security's {@code ReactiveJwtDecoders.fromIssuerLocation(...)} needs to validate
 * a brand's tokens with NO real Casdoor and NO network egress:
 *
 * <ul>
 *   <li>{@code GET /.well-known/openid-configuration} — the OIDC discovery doc
 *       (just enough: {@code issuer} + {@code jwks_uri});</li>
 *   <li>{@code GET /.well-known/jwks.json} — the brand's PUBLIC JWK set.</li>
 * </ul>
 *
 * <p>{@link #issuerUri()} is the value you put in {@code app.tenancy.issuers}
 * (issuer=domain). {@link #mint(String, List)} mints an RSA-signed JWT whose
 * {@code iss} is this server's issuer URI — so a token minted by issuer A is
 * cryptographically valid ONLY against issuer A's manager, which is exactly the
 * cross-brand isolation the slice asserts.
 *
 * <p>Deterministic: a fresh RSA keypair per instance, fixed loopback host, OS-picked
 * port. {@link AutoCloseable} so a try-with-resources / {@code @AfterEach} stops the
 * server. NEVER touches the network beyond {@code 127.0.0.1}.
 */
public final class TestIssuer implements AutoCloseable {

    private final RSAKey rsaKey;            // private+public — used to sign
    private final RSAKey publicKey;         // public-only — served at jwks_uri
    private final HttpServer server;
    private final String issuerUri;

    public TestIssuer() {
        try {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            this.publicKey = rsaKey.toPublicJWK();
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            int port = server.getAddress().getPort();
            this.issuerUri = "http://127.0.0.1:" + port;

            // OIDC discovery — fromIssuerLocation fetches this first, then jwks_uri.
            server.createContext("/.well-known/openid-configuration", exchange -> {
                String body = "{"
                        + "\"issuer\":\"" + issuerUri + "\","
                        + "\"jwks_uri\":\"" + issuerUri + "/.well-known/jwks.json\""
                        + "}";
                respond(exchange, body);
            });
            // The brand's public JWK set.
            server.createContext("/.well-known/jwks.json", exchange ->
                    respond(exchange, new JWKSet(publicKey).toString()));

            server.setExecutor(null);   // default executor — fine for a test fixture
            server.start();
        } catch (JOSEException | IOException e) {
            throw new IllegalStateException("failed to start TestIssuer", e);
        }
    }

    /** The issuer URI — use as the LHS of an {@code app.tenancy.issuers} pair. */
    public String issuerUri() {
        return issuerUri;
    }

    /**
     * Mint an RSA-signed JWT whose {@code iss} is THIS issuer, carrying the Casdoor
     * {@code roles} claim shape ({@code [{"name":"admin"}, ...]}) the converter reads.
     * exp is 5 min out; subject is the given {@code subject}. The token validates
     * ONLY against this issuer's manager (cross-brand isolation).
     */
    public String mint(String subject, List<String> roleNames) {
        List<Map<String, String>> roles = roleNames.stream()
                .map(r -> Map.of("name", r))
                .toList();
        return mintWithClaims(subject, Map.of("roles", roles, "name", subject));
    }

    /** Mint with an arbitrary claim map (iss/iat/exp/sub are still stamped here). */
    public String mintWithClaims(String subject, Map<String, Object> claims) {
        return mintWithExpiry(subject, claims, 300);
    }

    /**
     * ADDITIVE (negative-test support): mint a token whose {@code exp} is
     * {@code expirySeconds} relative to NOW — a NEGATIVE value yields a token that is
     * already EXPIRED (and whose {@code iat} is back-dated to keep iat &lt; exp), so
     * the resource-server's JWT timestamp validator rejects it. Everything else is
     * identical to {@link #mintWithClaims}: correctly RS256-signed by THIS issuer's
     * live key and carrying THIS issuer's {@code iss}, so the ONLY reason it fails is
     * the expiry — proving the timestamp gate, not signature/issuer.
     */
    public String mintWithExpiry(String subject, Map<String, Object> claims, long expirySeconds) {
        try {
            Instant now = Instant.now();
            Instant exp = now.plusSeconds(expirySeconds);
            // For an already-expired token keep iat strictly before exp (a back-dated
            // credential) so the only failing constraint is the expiry, not iat-in-future.
            Instant iat = expirySeconds < 0 ? exp.minusSeconds(60) : now;
            JWTClaimsSet.Builder cb = new JWTClaimsSet.Builder()
                    .issuer(issuerUri)
                    .subject(subject)
                    .issueTime(Date.from(iat))
                    .expirationTime(Date.from(exp));
            claims.forEach(cb::claim);
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                    cb.build());
            jwt.sign(new RSASSASigner(rsaKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to mint test JWT", e);
        }
    }

    /**
     * ADDITIVE (negative-test support): mint a token with the Casdoor {@code roles}
     * shape but ALREADY EXPIRED ({@code exp} in the past). The token is otherwise
     * pristine — correctly signed by this issuer's CURRENT key, carrying this issuer's
     * trusted {@code iss}. It is the canonical "stale credential" deny-leg: a caller
     * who WAS authorized presents a credential that has lapsed.
     */
    public String mintExpired(String subject, List<String> roleNames) {
        List<Map<String, String>> roles = roleNames.stream()
                .map(r -> Map.of("name", r))
                .toList();
        return mintWithExpiry(subject, Map.of("roles", roles, "name", subject), -300);
    }

    /**
     * ADDITIVE (negative-test support): mint a token that is STRUCTURALLY VALID and
     * carries THIS issuer's trusted {@code iss} and an unexpired {@code exp}, but is
     * signed by a FRESH keypair that this issuer's JWKS endpoint NEVER advertises. It
     * models a server-side credential REVOCATION / key de-provisioning (rotation): the
     * token looks legitimate in every observable way EXCEPT that its signature can no
     * longer be verified against the issuer's live JWKS — so the resource-server's
     * Nimbus signature step rejects it. Unlike a live key-rotation (which races the
     * decoder's JWK cache and is non-deterministic in-process), this is DETERMINISTIC:
     * the signing key with this {@code kid} is never served, so the lookup misses on
     * EVERY fetch, fresh or cached.
     *
     * <p>The header carries a NOVEL {@code kid} so a kid-aware decoder selects no key
     * (re-fetch still misses); even a kid-blind decoder that tries every published key
     * fails because none of them is the orphan signer.
     */
    public String mintRevoked(String subject, List<String> roleNames) {
        try {
            RSAKey orphanKey = new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())   // a kid the JWKS never serves
                    .generate();
            List<Map<String, String>> roles = roleNames.stream()
                    .map(r -> Map.of("name", r))
                    .toList();
            Instant now = Instant.now();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(issuerUri)                       // trusted iss
                    .subject(subject)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(300)))   // unexpired
                    .claim("roles", roles)
                    .claim("name", subject)
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(orphanKey.getKeyID()).build(),
                    claimsSet);
            jwt.sign(new RSASSASigner(orphanKey));           // signed by the orphan key
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to mint revoked test JWT", e);
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
