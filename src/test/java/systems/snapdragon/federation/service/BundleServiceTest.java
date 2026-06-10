package systems.snapdragon.federation.service;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.repository.UserModuleRepository;
import systems.snapdragon.federation.storage.BundleStorage;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Owner-scoped read-my-card-body + delete-my-bundle coverage (mocked repo +
 * storage, StepVerifier). Proves:
 * <ul>
 *   <li>read-body returns the caller's current entry-file bytes;</li>
 *   <li>a non-owner read finds no OWN active row -> 404 (never another user's
 *       bytes);</li>
 *   <li>delete-own supersedes the row AND removes the storage version (mirrors
 *       PUT supersession);</li>
 *   <li>delete of a slug the caller does not own -> 404, and NOTHING is removed
 *       from storage (no cross-tenant delete);</li>
 *   <li>an ADMIN caller reads/deletes the slug's active row regardless of owner;</li>
 *   <li>the entry filename defaults to remoteEntry.json for legacy rows.</li>
 * </ul>
 * Fully reactive — assertions use {@link StepVerifier}, no blocking.
 */
class BundleServiceTest {

    private static final String OWNER = "alice";
    private static final String OTHER = "bob";
    private static final String SLUG = "my-card";

    private static UserModule activeRow(String owner, String entryFile) {
        UserModule m = new UserModule();
        m.setId(7L);
        m.setOwnerUserId(owner);
        m.setSlug(SLUG);
        m.setVersionDir("file:/bundles/" + SLUG + "/deadbeef");
        m.setEntryFile(entryFile);
        m.setContentHash("deadbeef");
        m.setManifestJson("{}");
        m.setVisibility("internal");
        return m;
    }

    // ---------- read-my-card-body ----------

    @Test
    void readOwnBody_returnsEntryFileBytes() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule row = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, OWNER))
                .thenReturn(Mono.just(row));
        Resource bytes = new ByteArrayResource("<h1>hi</h1>".getBytes(StandardCharsets.UTF_8));
        when(storage.read("file:/bundles/" + SLUG + "/deadbeef", "card.html")).thenReturn(bytes);

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OWNER, SLUG, false))
                .assertNext(res -> assertThat(res).isSameAs(bytes))
                .verifyComplete();

        // Owner read NEVER consults the slug-only (admin) finder.
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
        verify(storage).read("file:/bundles/" + SLUG + "/deadbeef", "card.html");
    }

    @Test
    void readOwnBody_legacyRowWithoutEntryFile_defaultsToRemoteEntryJson() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule row = activeRow(OWNER, null); // pre-migration row
        when(repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, OWNER))
                .thenReturn(Mono.just(row));
        Resource bytes = new ByteArrayResource("{}".getBytes(StandardCharsets.UTF_8));
        when(storage.read("file:/bundles/" + SLUG + "/deadbeef", "remoteEntry.json")).thenReturn(bytes);

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OWNER, SLUG, false))
                .assertNext(res -> assertThat(res).isSameAs(bytes))
                .verifyComplete();
        verify(storage).read("file:/bundles/" + SLUG + "/deadbeef", "remoteEntry.json");
    }

    @Test
    void readOwnBody_nonOwner_hasNoOwnRow_so404() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // bob asks for alice's slug — the OWNER-scoped finder finds nothing for bob.
        when(repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, OTHER))
                .thenReturn(Mono.empty());

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OTHER, SLUG, false))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        // Never touched another user's bytes.
        verify(storage, never()).read(any(), any());
    }

    @Test
    void readOwnBody_admin_readsSlugActiveRow_regardlessOfOwner() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        // admin caller (bob with ROLE_ADMIN) reads via the slug-only finder.
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(aliceRow));
        Resource bytes = new ByteArrayResource("x".getBytes(StandardCharsets.UTF_8));
        when(storage.read(aliceRow.getVersionDir(), "card.html")).thenReturn(bytes);

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OTHER, SLUG, true))
                .assertNext(res -> assertThat(res).isSameAs(bytes))
                .verifyComplete();
        verify(repo).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG);
        verify(repo, never())
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
    }

    @Test
    void readOwnBody_entryFileGoneFromStorage_is404() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule row = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, OWNER))
                .thenReturn(Mono.just(row));
        when(storage.read(any(), any())).thenReturn(null); // file vanished

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OWNER, SLUG, false))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
    }

    // ---------- delete-my-bundle ----------

    @Test
    void deleteForOwner_supersedesRow_andRemovesStorageVersion() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule row = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, OWNER))
                .thenReturn(Mono.just(row));
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.deleteForOwner(OWNER, SLUG, false))
                .verifyComplete();

        // storage version removed (mirrors supersession cleanup) ...
        verify(storage).deleteVersion("file:/bundles/" + SLUG + "/deadbeef");
        // ... and the row marked superseded (not hard-deleted -> history queryable).
        assertThat(row.getSupersededAt()).isNotNull();
        verify(repo).save(eq(row));
    }

    @Test
    void deleteForOwner_nonOwner_is404_andNothingRemoved() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        when(repo.findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, OTHER))
                .thenReturn(Mono.empty());

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.deleteForOwner(OTHER, SLUG, false))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        // No cross-tenant delete: storage untouched, no save.
        verify(storage, never()).deleteVersion(any());
        verify(repo, never()).save(any());
    }

    @Test
    void deleteForOwner_admin_deletesSlugActiveRow_regardlessOfOwner() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(aliceRow));
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.deleteForOwner(OTHER, SLUG, true))
                .verifyComplete();
        verify(storage).deleteVersion(aliceRow.getVersionDir());
        assertThat(aliceRow.getSupersededAt()).isNotNull();
    }
}
