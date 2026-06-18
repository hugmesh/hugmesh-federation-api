package systems.snapdragon.federation.cache;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.cql.Row;
import com.datastax.oss.driver.api.core.cql.SimpleStatement;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import systems.snapdragon.federation.model.FederationManifestDto;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Cassandra-backed {@link ManifestCache}. Lifted from admin-bff's
 * {@code CassandraRouteMirror}: a lazily-built, gated {@link CqlSession} with
 * every blocking driver call wrapped on {@code boundedElastic} and any failure
 * swallowed so a missing / unreachable Cassandra never blocks the manifest read
 * path.
 *
 * <p>Active ONLY when {@code app.manifest-cache.cassandra.enabled=true} (default
 * false). The rendered manifest is stored as a single JSON blob under a fixed
 * partition key in
 * {@code <keyspace>.federation_manifest (id text PRIMARY KEY, body text, updated_at timestamp)}.
 *
 * <p><b>Ships-dark CQL auth + TLS (HELD until the Cassandra cluster is secured).</b>
 * Two NESTED flags, each defaulting OFF, layer credentials and SSL onto the
 * lazily-built session WITHOUT changing today's behaviour until an operator opts
 * in:
 * <ul>
 *   <li>{@code app.manifest-cache.cassandra.auth.enabled=true} (default false)
 *       adds {@code .withAuthCredentials(username, password)} (DataStax
 *       {@code PlainTextAuthProvider}). The password is sourced ONLY from an env
 *       var ({@code MANIFEST_CACHE_CASSANDRA_PASSWORD}) wired to a K8s/ESO Secret
 *       and is empty-defaulted in {@code application.yml} — never hardcoded.</li>
 *   <li>{@code app.manifest-cache.cassandra.ssl.enabled=true} (default false)
 *       adds {@code .withSslContext(...)} built from a PKCS12 truststore (the
 *       in-pod {@code build-keystore} initContainer pattern, same as the server
 *       mTLS path). The truststore password is read from the in-pod
 *       {@code application-tls.properties} location, never from git/yaml.</li>
 * </ul>
 * Both knobs are inert when unset: an empty/false value leaves the builder
 * exactly as it was. Because the session is built lazily on first use (not at
 * bean construction) and EVERY op swallows failures and degrades to the Postgres
 * render path, a wrong credential or untrusted cert never throws at startup —
 * it just logs + no-ops like an unreachable Cassandra.
 */
@Component
@ConditionalOnProperty(name = "app.manifest-cache.cassandra.enabled", havingValue = "true")
public class CassandraManifestCache implements ManifestCache {

    private static final Logger log = LoggerFactory.getLogger(CassandraManifestCache.class);
    private static final String KEY = "current";

    private final String contactPoint;
    private final String localDc;
    private final String keyspace;

    // ── Ships-dark CQL auth (default OFF) ────────────────────────────────────
    // When authEnabled is true the builder gets .withAuthCredentials(user, pass).
    // The password comes ONLY from MANIFEST_CACHE_CASSANDRA_PASSWORD (K8s/ESO
    // Secret env ref); it is empty-defaulted in application.yml — never hardcoded.
    private final boolean authEnabled;
    private final String authUsername;
    private final String authPassword;

    // ── Ships-dark CQL TLS (default OFF) ─────────────────────────────────────
    // When sslEnabled is true the builder gets .withSslContext(...) built from a
    // PKCS12 truststore (and optional keystore for mTLS). Store paths point at the
    // in-pod /stores tmpfs assembled by the build-keystore initContainer; store
    // passwords are read from those same in-pod locations, never from git/yaml.
    private final boolean sslEnabled;
    private final String sslTruststore;
    private final String sslTruststorePassword;
    private final String sslKeystore;
    private final String sslKeystorePassword;

    private final ObjectMapper mapper = new ObjectMapper();
    private volatile CqlSession session;

    public CassandraManifestCache(
            @Value("${app.manifest-cache.cassandra.contact-point:cassandra:9042}") String contactPoint,
            @Value("${app.manifest-cache.cassandra.local-dc:dc1}") String localDc,
            @Value("${app.manifest-cache.cassandra.keyspace:snapdragon_federation}") String keyspace,
            @Value("${app.manifest-cache.cassandra.auth.enabled:false}") boolean authEnabled,
            @Value("${app.manifest-cache.cassandra.auth.username:}") String authUsername,
            @Value("${app.manifest-cache.cassandra.auth.password:}") String authPassword,
            @Value("${app.manifest-cache.cassandra.ssl.enabled:false}") boolean sslEnabled,
            @Value("${app.manifest-cache.cassandra.ssl.truststore:}") String sslTruststore,
            @Value("${app.manifest-cache.cassandra.ssl.truststore-password:}") String sslTruststorePassword,
            @Value("${app.manifest-cache.cassandra.ssl.keystore:}") String sslKeystore,
            @Value("${app.manifest-cache.cassandra.ssl.keystore-password:}") String sslKeystorePassword) {
        this.contactPoint = contactPoint;
        this.localDc = localDc;
        this.keyspace = keyspace;
        this.authEnabled = authEnabled;
        this.authUsername = authUsername;
        this.authPassword = authPassword;
        this.sslEnabled = sslEnabled;
        this.sslTruststore = sslTruststore;
        this.sslTruststorePassword = sslTruststorePassword;
        this.sslKeystore = sslKeystore;
        this.sslKeystorePassword = sslKeystorePassword;
    }

    private CqlSession session() {
        CqlSession s = session;
        if (s != null) return s;
        synchronized (this) {
            if (session == null) {
                session = newSessionBuilder().build();
            }
            return session;
        }
    }

    /**
     * Builds the {@link CqlSessionBuilder} with the same contact-point / local-dc /
     * keyspace it always had, then layers in auth + TLS ONLY when the respective
     * nested flag is on. Package-visible (not private) so the unit test can assert
     * flag-on vs flag-off configuration WITHOUT a reachable Cassandra (the builder
     * is constructed, never {@code .build()}-dialled, in tests).
     *
     * <p>When both flags are off this returns exactly the legacy builder, so the
     * shipped-dark default is byte-for-byte the prior behaviour.
     */
    CqlSessionBuilder newSessionBuilder() {
        String[] hp = contactPoint.split(":", 2);
        int port = hp.length > 1 ? Integer.parseInt(hp[1].trim()) : 9042;
        CqlSessionBuilder builder = CqlSession.builder()
                .addContactPoint(new InetSocketAddress(hp[0].trim(), port))
                .withLocalDatacenter(localDc)
                .withKeyspace(keyspace);

        if (authEnabled) {
            // PlainTextAuthProvider via the driver builder. An empty username/
            // password would itself fail auth at the cluster — but that surfaces
            // on first use and is swallowed (degrade to Postgres), never at boot.
            builder = builder.withAuthCredentials(authUsername, authPassword);
            log.info("[manifest-cache] CQL auth ENABLED for Cassandra contact point (user={})",
                    authUsername.isBlank() ? "<unset>" : authUsername);
        }

        if (sslEnabled) {
            try {
                builder = builder.withSslContext(buildSslContext());
                log.info("[manifest-cache] CQL TLS ENABLED for Cassandra contact point (truststore={})",
                        sslTruststore.isBlank() ? "<jvm-default>" : sslTruststore);
            } catch (Exception e) {
                // Mis-configured store path/password must NOT throw at first-use
                // teardown of the whole cache; degrade like an unreachable cache.
                throw new IllegalStateException(
                        "manifest-cache CQL TLS is enabled but the SSL context could not be built", e);
            }
        }

        return builder;
    }

    /**
     * Builds an {@link SSLContext} from a PKCS12 truststore (server-cert trust) and,
     * when a keystore is also configured, a client identity for mTLS. All material
     * paths + passwords are operator-supplied via env/in-pod properties — this
     * method reads files, it never embeds any secret.
     */
    private SSLContext buildSslContext() throws Exception {
        KeyStore trust = loadStore(sslTruststore, sslTruststorePassword);
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust); // null trust => JVM default trust material

        javax.net.ssl.KeyManager[] keyManagers = null;
        if (sslKeystore != null && !sslKeystore.isBlank()) {
            KeyStore key = loadStore(sslKeystore, sslKeystorePassword);
            javax.net.ssl.KeyManagerFactory kmf = javax.net.ssl.KeyManagerFactory.getInstance(
                    javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(key, sslKeystorePassword == null ? new char[0] : sslKeystorePassword.toCharArray());
            keyManagers = kmf.getKeyManagers();
        }

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(keyManagers, tmf.getTrustManagers(), null);
        return ctx;
    }

    /** Loads a PKCS12 store from a path, or returns null when no path is configured. */
    private static KeyStore loadStore(String path, String password) throws Exception {
        if (path == null || path.isBlank()) return null;
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] pw = password == null ? new char[0] : password.toCharArray();
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            ks.load(in, pw);
        }
        return ks;
    }

    @Override
    public Mono<Void> put(FederationManifestDto manifest) {
        return Mono.<Void>fromRunnable(() -> {
            try {
                String body = mapper.writeValueAsString(manifest);
                session().execute(SimpleStatement.builder(
                        "INSERT INTO federation_manifest (id, body, updated_at) "
                        + "VALUES (?, ?, toTimestamp(now()))")
                        .addPositionalValues(KEY, body).build());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).subscribeOn(Schedulers.boundedElastic())
          .onErrorResume(e -> {
              log.warn("[manifest-cache] best-effort put failed: {} (read path still serves from Postgres)",
                      e.toString());
              return Mono.empty();
          }).then();
    }

    @Override
    public Mono<FederationManifestDto> get() {
        return Mono.fromCallable(() -> {
            Row row = session().execute(SimpleStatement.builder(
                    "SELECT body FROM federation_manifest WHERE id = ?")
                    .addPositionalValue(KEY).build()).one();
            if (row == null) return null;
            String body = row.getString("body");
            if (body == null || body.isBlank()) return null;
            return mapper.readValue(body, FederationManifestDto.class);
        }).subscribeOn(Schedulers.boundedElastic())
          .onErrorResume(e -> {
              log.warn("[manifest-cache] best-effort get failed: {} (rendering from Postgres)", e.toString());
              return Mono.empty();
          });
    }

    @Override
    public Mono<Void> invalidate() {
        return Mono.<Void>fromRunnable(() ->
                session().execute(SimpleStatement.builder(
                        "DELETE FROM federation_manifest WHERE id = ?")
                        .addPositionalValue(KEY).build()))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.warn("[manifest-cache] best-effort invalidate failed: {} "
                            + "(Postgres render already excludes the banned modules)", e.toString());
                    return Mono.empty();
                }).then();
    }

    @Override
    public String label() {
        return "cassandra";
    }

    @PreDestroy
    void close() {
        CqlSession s = session;
        if (s != null) {
            try { s.close(); } catch (Exception ignore) { /* shutting down */ }
        }
    }
}
