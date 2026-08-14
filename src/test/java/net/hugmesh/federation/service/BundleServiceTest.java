package net.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.federation.model.UserModule;
import net.hugmesh.federation.repository.UserModuleRepository;
import net.hugmesh.commons.security.PrincipalDomain;
import net.hugmesh.federation.storage.BundleStorage;

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
 *   <li>a per-domain ADMIN reads/deletes/supersedes the slug's OWN-BRAND active row
 *       (via the domain-pinned active finder), and a SUPERADMIN reaches any brand;</li>
 *   <li>the entry filename defaults to remoteEntry.json for legacy rows.</li>
 * </ul>
 * Fully reactive — assertions use {@link StepVerifier}, no blocking.
 */
class BundleServiceTest {

    private static final String OWNER = "alice";
    private static final String OTHER = "bob";
    private static final String SLUG = "my-card";
    private static final String DOMAIN = "brandx";

    /** A per-domain (non-superadmin) scope for the brand the seeded rows live in. */
    private static final PrincipalDomain SCOPE = PrincipalDomain.forDomain(DOMAIN);
    /** The unscoped SUPERADMIN scope (reaches any brand). */
    private static final PrincipalDomain SUPERADMIN = PrincipalDomain.superadminFor(DOMAIN);

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

        StepVerifier.create(svc.readOwnBody(OWNER, SLUG, false, SCOPE))
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

        StepVerifier.create(svc.readOwnBody(OWNER, SLUG, false, SCOPE))
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

        StepVerifier.create(svc.readOwnBody(OTHER, SLUG, false, SCOPE))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        // Never touched another user's bytes.
        verify(storage, never()).read(any(), any());
    }

    @Test
    void readOwnBody_perDomainAdmin_readsOwnBrandSlugActiveRow_regardlessOfOwner() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        // per-domain admin caller (bob with ROLE_ADMIN, scope brandx) reads via the
        // DOMAIN-pinned active finder — never the brand-blind slug-only finder.
        when(repo.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN))
                .thenReturn(Mono.just(aliceRow));
        Resource bytes = new ByteArrayResource("x".getBytes(StandardCharsets.UTF_8));
        when(storage.read(aliceRow.getVersionDir(), "card.html")).thenReturn(bytes);

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OTHER, SLUG, true, SCOPE))
                .assertNext(res -> assertThat(res).isSameAs(bytes))
                .verifyComplete();
        verify(repo).findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN);
        // a per-domain admin must NOT reach the brand-blind slug-only finder (the IDOR vector).
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
        verify(repo, never())
                .findFirstBySlugAndOwnerUserIdAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
    }

    @Test
    void readOwnBody_perDomainAdmin_foreignBrandSlug_is404_neverCrossTenantBytes() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // The slug's only active row lives in brandy; a brandx admin must NOT see it.
        // The domain-pinned finder for brandx resolves EMPTY -> 404, never the foreign row.
        when(repo.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN))
                .thenReturn(Mono.empty());

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OTHER, SLUG, true, SCOPE))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        // FAIL-FIRST: against the unfixed code the slug-only finder WOULD have returned the
        // brandy row and streamed its bytes. Assert that finder is never even consulted.
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
        verify(storage, never()).read(any(), any());
    }

    @Test
    void readOwnBody_superadmin_readsSlugActiveRow_anyBrand() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        // SUPERADMIN keeps the un-pinned slug-only finder (reaches any brand).
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(aliceRow));
        Resource bytes = new ByteArrayResource("x".getBytes(StandardCharsets.UTF_8));
        when(storage.read(aliceRow.getVersionDir(), "card.html")).thenReturn(bytes);

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.readOwnBody(OTHER, SLUG, true, SUPERADMIN))
                .assertNext(res -> assertThat(res).isSameAs(bytes))
                .verifyComplete();
        verify(repo).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG);
        verify(repo, never())
                .findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
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

        StepVerifier.create(svc.readOwnBody(OWNER, SLUG, false, SCOPE))
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

        StepVerifier.create(svc.deleteForOwner(OWNER, SLUG, false, SCOPE))
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

        StepVerifier.create(svc.deleteForOwner(OTHER, SLUG, false, SCOPE))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        // No cross-tenant delete: storage untouched, no save.
        verify(storage, never()).deleteVersion(any());
        verify(repo, never()).save(any());
    }

    @Test
    void deleteForOwner_perDomainAdmin_deletesOwnBrandSlugActiveRow_regardlessOfOwner() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        // per-domain admin: deletes via the DOMAIN-pinned active finder (own brand only).
        when(repo.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN))
                .thenReturn(Mono.just(aliceRow));
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.deleteForOwner(OTHER, SLUG, true, SCOPE))
                .verifyComplete();
        verify(storage).deleteVersion(aliceRow.getVersionDir());
        assertThat(aliceRow.getSupersededAt()).isNotNull();
        // never the brand-blind slug-only finder.
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
    }

    @Test
    void deleteForOwner_perDomainAdmin_foreignBrandSlug_is404_andNothingDestroyed() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // The slug's only active row lives in brandy; a brandx admin must NOT destroy it.
        // The domain-pinned finder for brandx resolves EMPTY -> 404, victim row untouched.
        when(repo.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN))
                .thenReturn(Mono.empty());

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.deleteForOwner(OTHER, SLUG, true, SCOPE))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        // FAIL-FIRST: against the unfixed code the slug-only finder WOULD have returned the
        // brandy row and DELETED it. No storage delete, no save, slug-only finder untouched.
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
        verify(storage, never()).deleteVersion(any());
        verify(repo, never()).save(any());
    }

    @Test
    void deleteForOwner_superadmin_deletesSlugActiveRow_anyBrand() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        // SUPERADMIN keeps the un-pinned slug-only finder (reaches any brand).
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(aliceRow));
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.deleteForOwner(OTHER, SLUG, true, SUPERADMIN))
                .verifyComplete();
        verify(storage).deleteVersion(aliceRow.getVersionDir());
        assertThat(aliceRow.getSupersededAt()).isNotNull();
        verify(repo, never())
                .findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
    }

    // ---------- PUT: owner-scoped supersede (BFLA / cross-owner write) ----------
    //
    // Finding A01 / CWE-639: a PUT used the slug-only active finder to supersede,
    // so any user could displace ANOTHER user's active bundle by PUTting to their
    // slug. These prove the owner-scoped fail-closed fix.

    /** A staging body the PUT pipeline can write + hash (one DataBuffer). */
    private static reactor.core.publisher.Flux<org.springframework.core.io.buffer.DataBuffer> body(String s) {
        org.springframework.core.io.buffer.DataBufferFactory f =
                new org.springframework.core.io.buffer.DefaultDataBufferFactory();
        return reactor.core.publisher.Flux.just(f.wrap(s.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void put_crossOwner_supersede_isDenied_andVictimRowUntouched() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // The slug's CURRENT active row belongs to alice; bob (non-admin) PUTs to it.
        UserModule victim = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(victim));
        when(storage.installFromStaging(eq(SLUG), any(), any())).thenReturn("file:/bundles/" + SLUG + "/newhash");

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.put(OTHER, SLUG, "card.html", "internal", "{}", false,
                        PrincipalDomain.forDomain("default"), body("<h1>pwn</h1>")))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(409))
                .verify();

        // The victim's active row is NEVER superseded, and NO new (attacker) row is saved.
        assertThat(victim.getSupersededAt()).isNull();
        verify(repo, never()).save(any(UserModule.class));
    }

    @Test
    void put_sameOwner_supersedesOwnActiveRow_andInsertsNewVersion() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // alice already has an active row for the slug; alice PUTs a new version.
        UserModule own = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(own));
        when(storage.installFromStaging(eq(SLUG), any(), any())).thenReturn("file:/bundles/" + SLUG + "/newhash");
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.put(OWNER, SLUG, "card.html", "internal", "{}", false,
                        PrincipalDomain.forDomain("default"), body("<h1>v2</h1>")))
                .assertNext(saved -> {
                    assertThat(saved.getOwnerUserId()).isEqualTo(OWNER);
                    assertThat(saved.getVersionDir()).isEqualTo("file:/bundles/" + SLUG + "/newhash");
                })
                .verifyComplete();

        // Own prior row superseded, then the new version inserted (two saves).
        assertThat(own.getSupersededAt()).isNotNull();
        verify(repo, org.mockito.Mockito.times(2)).save(any(UserModule.class));
    }

    @Test
    void put_perDomainAdmin_supersedesAnotherOwnersOwnBrandActiveRow() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // alice's row is active in brandx; a brandx ADMIN (bob) PUTs to the slug — allowed
        // override, resolved via the DOMAIN-pinned prior-active finder (own brand only).
        UserModule aliceRow = activeRow(OWNER, "card.html");
        when(repo.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN))
                .thenReturn(Mono.just(aliceRow));
        when(storage.installFromStaging(eq(SLUG), any(), any())).thenReturn("file:/bundles/" + SLUG + "/adminhash");
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.put(OTHER, SLUG, "card.html", "internal", "{}", true,
                        SCOPE, body("<h1>admin</h1>")))
                .assertNext(saved -> assertThat(saved.getOwnerUserId()).isEqualTo(OTHER))
                .verifyComplete();

        assertThat(aliceRow.getSupersededAt()).isNotNull();
        // never the brand-blind slug-only finder.
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
    }

    @Test
    void put_perDomainAdmin_foreignBrandActiveRow_isInvisible_doesNotDisplaceVictim() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // The slug's active row lives in brandy (owned by alice-y). A brandx ADMIN PUTs to
        // the slug: the DOMAIN-pinned prior-active finder for brandx resolves EMPTY, so the
        // PUT is a first-publish IN BRANDX and the brandy victim row is NEVER superseded.
        UserModule brandYVictim = activeRow("alice-y", "card.html");
        when(repo.findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG, DOMAIN))
                .thenReturn(Mono.empty());
        when(storage.installFromStaging(eq(SLUG), any(), any())).thenReturn("file:/bundles/" + SLUG + "/xhash");
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.put(OTHER, SLUG, "card.html", "internal", "{}", true,
                        SCOPE, body("<h1>x-admin</h1>")))
                .assertNext(saved -> assertThat(saved.getOwnerUserId()).isEqualTo(OTHER))
                .verifyComplete();

        // MUTATION-RESISTANT / FAIL-FIRST: against the unfixed slug-only supersede the
        // brandy victim row WOULD have been stamped superseded. It must stay untouched.
        assertThat(brandYVictim.getSupersededAt())
                .as("a per-domain admin PUT must not supersede a foreign brand's active card")
                .isNull();
        verify(repo, never()).findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(any());
        // exactly one save: the new brandx insert, never a supersede of the brandy row.
        verify(repo, org.mockito.Mockito.times(1)).save(any(UserModule.class));
    }

    @Test
    void put_superadmin_supersedesSlugActiveRow_anyBrand() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        UserModule aliceRow = activeRow(OWNER, "card.html");
        // SUPERADMIN keeps the un-pinned slug-only prior-active finder (reaches any brand).
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.just(aliceRow));
        when(storage.installFromStaging(eq(SLUG), any(), any())).thenReturn("file:/bundles/" + SLUG + "/sahash");
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.put(OTHER, SLUG, "card.html", "internal", "{}", true,
                        SUPERADMIN, body("<h1>sa</h1>")))
                .assertNext(saved -> assertThat(saved.getOwnerUserId()).isEqualTo(OTHER))
                .verifyComplete();

        assertThat(aliceRow.getSupersededAt()).isNotNull();
        verify(repo, never())
                .findFirstBySlugAndDomainAndSupersededAtIsNullOrderByCreatedAtDesc(any(), any());
    }

    @Test
    void put_firstPublish_noActiveRow_insertsWithoutSupersede() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        // No active row for the slug — a first publish; nothing to supersede.
        when(repo.findFirstBySlugAndSupersededAtIsNullOrderByCreatedAtDesc(SLUG))
                .thenReturn(Mono.empty());
        when(storage.installFromStaging(eq(SLUG), any(), any())).thenReturn("file:/bundles/" + SLUG + "/firsthash");
        when(repo.save(any(UserModule.class))).thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        BundleService svc = new BundleService(repo, storage);

        StepVerifier.create(svc.put(OWNER, SLUG, "card.html", "internal", "{}", false,
                        PrincipalDomain.forDomain("default"), body("<h1>first</h1>")))
                .assertNext(saved -> assertThat(saved.getOwnerUserId()).isEqualTo(OWNER))
                .verifyComplete();

        // Exactly one save (the insert) — no supersede save.
        verify(repo, org.mockito.Mockito.times(1)).save(any(UserModule.class));
    }
}
