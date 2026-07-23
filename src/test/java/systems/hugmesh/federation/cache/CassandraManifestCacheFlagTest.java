package systems.hugmesh.federation.cache;

import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.auth.AuthProvider;
import com.datastax.oss.driver.api.core.session.ProgrammaticArguments;
import com.datastax.oss.driver.api.core.ssl.SslEngineFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.TrustManagerFactory;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ships-dark verification for the nested CQL auth + TLS flags on
 * {@link CassandraManifestCache}. The whole point is that with the flags OFF
 * (the default) the session builder is byte-for-byte the legacy anonymous +
 * plaintext one, and ONLY when an operator flips a nested flag does the builder
 * gain credentials / an SSL engine.
 *
 * <p>It asserts on {@link CassandraManifestCache#newSessionBuilder()} (which
 * constructs the {@link CqlSessionBuilder} but never {@code .build()}-dials a
 * cluster) so the test needs no reachable Cassandra. The auth provider and SSL
 * engine factory the builder will use are read back from the driver's
 * package-visible {@code programmaticArgumentsBuilder} via reflection and its
 * public {@link ProgrammaticArguments} getters — no secret or live socket is
 * involved.
 */
class CassandraManifestCacheFlagTest {

    /** Constructs the cache with auth + ssl explicitly OFF (the shipped default). */
    private static CassandraManifestCache flagsOff() {
        return new CassandraManifestCache(
                "cassandra:9042", "dc1", "snapdragon_federation",
                /* authEnabled */ false, "", "",
                /* sslEnabled  */ false, "", "", "", "");
    }

    private static ProgrammaticArguments programmaticArgs(CqlSessionBuilder builder) throws Exception {
        // SessionBuilder#programmaticArgumentsBuilder is protected; reach it to read
        // back what auth/ssl the builder is configured to dial with.
        Field f = builder.getClass().getSuperclass().getDeclaredField("programmaticArgumentsBuilder");
        f.setAccessible(true);
        ProgrammaticArguments.Builder pab = (ProgrammaticArguments.Builder) f.get(builder);
        return pab.build();
    }

    @Test
    void flagsOff_buildsLegacyAnonymousPlaintextSession_noAuth_noSsl() throws Exception {
        ProgrammaticArguments args = programmaticArgs(flagsOff().newSessionBuilder());

        assertThat(args.getAuthProvider())
                .as("auth flag OFF must not attach any AuthProvider (anonymous, as today)")
                .isNull();
        assertThat(args.getSslEngineFactory())
                .as("ssl flag OFF must not attach any SslEngineFactory (plaintext, as today)")
                .isNull();
    }

    @Test
    void authFlagOn_attachesPlainTextCredentials() throws Exception {
        CassandraManifestCache cache = new CassandraManifestCache(
                "cassandra:9042", "dc1", "snapdragon_federation",
                /* authEnabled */ true, "fed_app", "s3cret-from-env-only",
                /* sslEnabled  */ false, "", "", "", "");

        AuthProvider auth = programmaticArgs(cache.newSessionBuilder()).getAuthProvider();
        assertThat(auth)
                .as("auth flag ON must attach a PlainText AuthProvider built from the env-sourced creds")
                .isNotNull();
        // .withAuthCredentials wires the driver's internal ProgrammaticPlainTextAuthProvider.
        assertThat(auth.getClass().getName()).containsIgnoringCase("PlainText");
    }

    @Test
    void sslFlagOn_attachesSslEngineFactory_fromTruststore(@TempDir Path dir) throws Exception {
        // Generate a throwaway PKCS12 truststore at TEST RUNTIME (never committed) so
        // the ssl-on path builds a real SSLContext from a real store, proving the
        // truststore-load + .withSslContext wiring works end to end.
        Path truststore = dir.resolve("cassandra-truststore.p12");
        String storePw = "test-only-not-a-secret";
        writeEmptyPkcs12(truststore, storePw);

        CassandraManifestCache cache = new CassandraManifestCache(
                "cassandra:9042", "dc1", "snapdragon_federation",
                /* authEnabled */ false, "", "",
                /* sslEnabled  */ true, truststore.toString(), storePw, "", "");

        SslEngineFactory ssl = programmaticArgs(cache.newSessionBuilder()).getSslEngineFactory();
        assertThat(ssl)
                .as("ssl flag ON must attach an SslEngineFactory built from the configured truststore")
                .isNotNull();
    }

    @Test
    void bothFlagsOn_attachesBothAuthAndSsl(@TempDir Path dir) throws Exception {
        Path truststore = dir.resolve("cassandra-truststore.p12");
        String storePw = "test-only-not-a-secret";
        writeEmptyPkcs12(truststore, storePw);

        CassandraManifestCache cache = new CassandraManifestCache(
                "cassandra:9042", "dc1", "snapdragon_federation",
                /* authEnabled */ true, "fed_app", "s3cret-from-env-only",
                /* sslEnabled  */ true, truststore.toString(), storePw, "", "");

        ProgrammaticArguments args = programmaticArgs(cache.newSessionBuilder());
        assertThat(args.getAuthProvider()).isNotNull();
        assertThat(args.getSslEngineFactory()).isNotNull();
    }

    /** Sanity-check that the test truststore is a valid PKCS12 trust source. */
    private static void writeEmptyPkcs12(Path path, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password.toCharArray());
        try (OutputStream out = Files.newOutputStream(path)) {
            ks.store(out, password.toCharArray());
        }
        // Confirm it loads as trust material (mirrors what the production code does).
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
    }
}
