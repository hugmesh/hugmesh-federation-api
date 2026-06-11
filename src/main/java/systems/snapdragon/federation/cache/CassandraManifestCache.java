package systems.snapdragon.federation.cache;

import com.datastax.oss.driver.api.core.CqlSession;
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

import java.net.InetSocketAddress;

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
 */
@Component
@ConditionalOnProperty(name = "app.manifest-cache.cassandra.enabled", havingValue = "true")
public class CassandraManifestCache implements ManifestCache {

    private static final Logger log = LoggerFactory.getLogger(CassandraManifestCache.class);
    private static final String KEY = "current";

    private final String contactPoint;
    private final String localDc;
    private final String keyspace;
    private final ObjectMapper mapper = new ObjectMapper();
    private volatile CqlSession session;

    public CassandraManifestCache(
            @Value("${app.manifest-cache.cassandra.contact-point:cassandra:9042}") String contactPoint,
            @Value("${app.manifest-cache.cassandra.local-dc:dc1}") String localDc,
            @Value("${app.manifest-cache.cassandra.keyspace:snapdragon_federation}") String keyspace) {
        this.contactPoint = contactPoint;
        this.localDc = localDc;
        this.keyspace = keyspace;
    }

    private CqlSession session() {
        CqlSession s = session;
        if (s != null) return s;
        synchronized (this) {
            if (session == null) {
                String[] hp = contactPoint.split(":", 2);
                int port = hp.length > 1 ? Integer.parseInt(hp[1].trim()) : 9042;
                session = CqlSession.builder()
                        .addContactPoint(new InetSocketAddress(hp[0].trim(), port))
                        .withLocalDatacenter(localDc)
                        .withKeyspace(keyspace)
                        .build();
            }
            return session;
        }
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
