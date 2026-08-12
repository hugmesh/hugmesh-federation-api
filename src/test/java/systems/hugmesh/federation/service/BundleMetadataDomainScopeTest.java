package systems.hugmesh.federation.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.federation.model.UserModule;
import systems.hugmesh.federation.model.UserModuleView;
import systems.hugmesh.federation.repository.UserModuleRepository;
import net.hugmesh.commons.security.PrincipalDomain;
import systems.hugmesh.federation.storage.BundleStorage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * BUG-B (cross-tenant metadata IDOR) proof for the bundle METADATA reads
 * ({@code listForSlug} / {@code byContentHash}). Both were {@code .authenticated()}
 * only with NO owner/domain cut and returned the FULL {@link UserModule}
 * ({@code ownerUserId}, {@code versionDir}, {@code manifestJson}, {@code visibility}).
 *
 * <p>Proven here (mocked repo + storage, StepVerifier):
 * <ul>
 *   <li><b>finder selection per tier</b> — a per-domain NON-admin uses the
 *       DOMAIN+OWNER-pinned finder; a per-domain ADMIN the DOMAIN-pinned finder;
 *       SUPERADMIN the un-pinned finder. The unscoped slug-only / hash-only finders
 *       are NEVER used for a per-domain non-admin (the unfixed leak path).</li>
 *   <li><b>public-safe projection</b> — the returned shape is {@link UserModuleView},
 *       which omits {@code versionDir} + {@code ownerUserId} (compile-time + value
 *       guard).</li>
 *   <li><b>cross-tenant / cross-owner 404</b> — a hash the pinned finder cannot
 *       resolve is a 404, never a foreign row.</li>
 * </ul>
 *
 * <p>FAIL-FIRST: against the unfixed service these tests do not even compile (the
 * methods took no PrincipalDomain/owner/admin and returned UserModule); behaviourally,
 * the verify(never()) on the unscoped finders + the no-versionDir/ownerUserId guard
 * are exactly what the leak violated.
 */
class BundleMetadataDomainScopeTest {

    private static final String SLUG = "my-card";
    private static final String HASH = "a".repeat(64);

    private static UserModule row(String owner, String domain) {
        UserModule m = new UserModule();
        m.setId(7L);
        m.setOwnerUserId(owner);
        m.setSlug(SLUG);
        m.setVersionDir("file:/bundles/" + SLUG + "/" + HASH); // MUST NOT leak
        m.setEntryFile("card.html");
        m.setContentHash(HASH);
        m.setManifestJson("{\"name\":\"card\"}");
        m.setVisibility("internal");
        m.setDomain(domain);
        return m;
    }

    // ---------- listForSlug ----------

    @Test
    void listForSlug_nonAdmin_usesDomainAndOwnerFinder_projectsPublicSafe() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        BundleStorage storage = mock(BundleStorage.class);
        when(repo.findBySlugAndDomainAndOwnerUserIdOrderByCreatedAtDesc(SLUG, "brandx", "alice"))
                .thenReturn(Flux.just(row("alice", "brandx")));
        BundleService svc = new BundleService(repo, storage);

        UserModuleView view = svc.listForSlug(SLUG, PrincipalDomain.forDomain("brandx"), "alice", false)
                .blockFirst();

        assertThat(view).isNotNull();
        assertThat(view.slug()).isEqualTo(SLUG);
        assertThat(view.contentHash()).isEqualTo(HASH);
        // The unscoped slug-only finder (the unfixed cross-tenant leak) is NEVER used.
        verify(repo).findBySlugAndDomainAndOwnerUserIdOrderByCreatedAtDesc(SLUG, "brandx", "alice");
        verify(repo, never()).findBySlugOrderByCreatedAtDesc(ArgumentMatchers.any());
        verify(repo, never()).findBySlugAndDomainOrderByCreatedAtDesc(ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void listForSlug_admin_usesDomainFinder_anyOwner() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        when(repo.findBySlugAndDomainOrderByCreatedAtDesc(SLUG, "brandx"))
                .thenReturn(Flux.just(row("someone-else", "brandx")));
        BundleService svc = new BundleService(repo, mock(BundleStorage.class));

        svc.listForSlug(SLUG, PrincipalDomain.forDomain("brandx"), "admin-sub", true).collectList().block();

        verify(repo).findBySlugAndDomainOrderByCreatedAtDesc(SLUG, "brandx");
        verify(repo, never()).findBySlugOrderByCreatedAtDesc(ArgumentMatchers.any());
        verify(repo, never())
                .findBySlugAndDomainAndOwnerUserIdOrderByCreatedAtDesc(ArgumentMatchers.any(),
                        ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    @Test
    void listForSlug_superadmin_usesUnpinnedFinder() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        when(repo.findBySlugOrderByCreatedAtDesc(SLUG))
                .thenReturn(Flux.just(row("anyone", "brandy")));
        BundleService svc = new BundleService(repo, mock(BundleStorage.class));

        svc.listForSlug(SLUG, PrincipalDomain.superadminFor(null), "root", true).collectList().block();

        verify(repo).findBySlugOrderByCreatedAtDesc(SLUG);
        verify(repo, never()).findBySlugAndDomainOrderByCreatedAtDesc(ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    // ---------- byContentHash ----------

    @Test
    void byContentHash_nonAdmin_usesDomainAndOwnerFinder_projectsPublicSafe() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        when(repo.findByContentHashAndDomainAndOwnerUserId(HASH, "brandx", "alice"))
                .thenReturn(Mono.just(row("alice", "brandx")));
        BundleService svc = new BundleService(repo, mock(BundleStorage.class));

        UserModuleView view = svc.byContentHash(HASH, PrincipalDomain.forDomain("brandx"), "alice", false).block();

        assertThat(view).isNotNull();
        assertThat(view.contentHash()).isEqualTo(HASH);
        verify(repo).findByContentHashAndDomainAndOwnerUserId(HASH, "brandx", "alice");
        // The unscoped hash finder (the cross-tenant pivot) is NEVER used for a non-admin.
        verify(repo, never()).findByContentHash(ArgumentMatchers.any());
    }

    @Test
    void byContentHash_crossTenant_emptyFinder_is404_neverForeignRow() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        // brand-X non-admin asks for a hash that lives in brand-Y: the pinned finder is
        // empty (the real query would never match the foreign row) => 404.
        when(repo.findByContentHashAndDomainAndOwnerUserId(HASH, "brandx", "alice"))
                .thenReturn(Mono.empty());
        BundleService svc = new BundleService(repo, mock(BundleStorage.class));

        StepVerifier.create(svc.byContentHash(HASH, PrincipalDomain.forDomain("brandx"), "alice", false))
                .expectErrorSatisfies(e -> assertThat(
                        ((org.springframework.web.server.ResponseStatusException) e).getStatusCode().value())
                        .isEqualTo(404))
                .verify();
        verify(repo, never()).findByContentHash(ArgumentMatchers.any());
    }

    @Test
    void byContentHash_superadmin_usesUnpinnedFinder() {
        UserModuleRepository repo = mock(UserModuleRepository.class);
        when(repo.findByContentHash(HASH)).thenReturn(Mono.just(row("anyone", "brandy")));
        BundleService svc = new BundleService(repo, mock(BundleStorage.class));

        UserModuleView view = svc.byContentHash(HASH, PrincipalDomain.superadminFor(null), "root", true).block();

        assertThat(view).isNotNull();
        verify(repo).findByContentHash(HASH);
        verify(repo, never())
                .findByContentHashAndDomain(ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    // ---------- public-safe shape (compile-time guard) ----------

    @Test
    void view_hasNoVersionDirNorOwnerUserId_component() {
        var names = java.util.Arrays.stream(UserModuleView.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName).toList();
        assertThat(names)
                .doesNotContain("versionDir")
                .doesNotContain("ownerUserId")
                .doesNotContain("domain");
        // The legitimate, public-safe fields ARE present.
        assertThat(names).contains("slug", "contentHash", "manifestJson", "visibility");
    }
}
