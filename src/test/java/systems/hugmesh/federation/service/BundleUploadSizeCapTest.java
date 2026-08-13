package systems.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.model.UserModule;
import systems.hugmesh.federation.repository.UserModuleRepository;
import systems.hugmesh.federation.storage.BundleStorage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the bundle-PUT upload size cap (DoS-unbounded finding):
 * {@code BundleService.writeStagedBody} streams the raw {@code Flux<DataBuffer>} body
 * straight to disk with no ceiling, so any authenticated caller could PUT a multi-GB /
 * infinite chunked octet-stream and exhaust the bundles volume.
 *
 * <p>These prove the fix:
 * <ul>
 *   <li>an over-limit body errors with 413 BEFORE the tree is hashed/installed, and the
 *       partial staging dir is cleaned up (no orphaned bytes left on disk);</li>
 *   <li>a body within the limit still stages, installs, and inserts a new active row
 *       exactly as before (no legitimate caller is broken).</li>
 * </ul>
 * Fully reactive — assertions use {@link StepVerifier}, no live infra.
 */
class BundleUploadSizeCapTest {

    private static final String OWNER = "alice";
    private static final String SLUG = "my-card";
    private static final PrincipalDomain SCOPE = PrincipalDomain.forDomain("default");

    /** A staging body of {@code count} buffers, each {@code per} bytes (deterministic size). */
    private static Flux<DataBuffer> body(int count, int per) {
        DataBufferFactory f = new DefaultDataBufferFactory();
        byte[] chunk = new byte[per];
        return Flux.range(0, count).map(i -> f.wrap(chunk.clone()));
    }

    private static long stagingDirCount() throws IOException {
        Path tmp = Path.of(System.getProperty("java.io.tmpdir"));
        try (Stream<Path> s = Files.list(tmp)) {
            return s.filter(p -> p.getFileName().toString().startsWith("fed-stage-")).count();
        }
    }

    @Test
    void put_bodyOverLimit_is413_neverInstalls_andCleansStaging() throws IOException {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // First-publish so the owner-scoped supersede branch is not the thing under test.
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.empty());

        // Tiny ceiling (100 bytes) so a small body trips it without allocating gigabytes.
        BundleService svc = new BundleService(repo, storage, 100L);

        long before = stagingDirCount();

        // 10 buffers x 64 bytes = 640 bytes >> the 100-byte cap.
        StepVerifier.create(svc.put(OWNER, SLUG, "card.html", "internal", "{}", false,
                        SCOPE, body(10, 64)))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(413))
                .verify();

        // The over-limit body is rejected BEFORE hashing/installing or any DB insert.
        verify(storage, never()).installFromStaging(any(), any(), any());
        verify(repo, never()).save(any(UserModule.class));

        // The partial staging dir is cleaned up — no orphaned bytes left on the volume.
        // (doOnError cleanup runs on boundedElastic; poll briefly until it settles.)
        for (int i = 0; i < 50 && stagingDirCount() > before; i++) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
        assertThat(stagingDirCount())
                .as("rejected over-limit upload must leave no fed-stage-* dir behind")
                .isEqualTo(before);
    }

    @Test
    void put_bodyWithinLimit_stillStagesInstallsAndInserts() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.empty()); // first publish
        when(storage.installFromStaging(eq(SLUG), any(), any()))
                .thenReturn("file:/bundles/" + SLUG + "/okhash");
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        // Default ceiling (256 MiB); a few hundred bytes is well within it.
        BundleService svc = new BundleService(repo, storage);

        Flux<DataBuffer> small = Flux.just(new DefaultDataBufferFactory()
                .wrap("<h1>legit card body</h1>".getBytes(StandardCharsets.UTF_8)));

        StepVerifier.create(svc.put(OWNER, SLUG, "card.html", "internal", "{}", false, SCOPE, small))
                .assertNext(saved -> {
                    assertThat(saved.getOwnerUserId()).isEqualTo(OWNER);
                    assertThat(saved.getVersionDir()).isEqualTo("file:/bundles/" + SLUG + "/okhash");
                })
                .verifyComplete();

        verify(storage).installFromStaging(eq(SLUG), any(), any());
        verify(repo).save(any(UserModule.class));
    }
}
