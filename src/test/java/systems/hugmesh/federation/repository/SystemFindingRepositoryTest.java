package systems.hugmesh.federation.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import reactor.test.StepVerifier;
import systems.hugmesh.federation.config.R2dbcConvertersConfig;
import systems.hugmesh.federation.model.SystemFinding;
import systems.hugmesh.federation.support.TestDatabaseConfig;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice for system_findings over H2 (PG-compat) + the real Liquibase changelog.
 * Confirms the 036/037 DDL applies and that {@code subject_ref} (037) round-trips:
 * a finding filed WITH a back-reference reads it back, the surface-level avatar/profile
 * path (no subjectRef) reads back NULL, and resolve loads the row with subjectRef intact
 * (so the controller resolve response echoes it). The composite (surface, status) index
 * from 037 backs the future reconcile read; this proves the column it indexes exists.
 */
@DataR2dbcTest
@Import({TestDatabaseConfig.class, R2dbcConvertersConfig.class})
class SystemFindingRepositoryTest {

    @Autowired SystemFindingRepository findings;

    private static SystemFinding held(String subject, String surface, String subjectRef) {
        SystemFinding f = new SystemFinding();
        f.setReporter("@system");
        f.setSubject(subject);
        f.setSurface(surface);
        f.setDisposition("flagged");
        f.setStatus("held");
        f.setSubjectRef(subjectRef);
        f.setDomain("default");
        f.setTs(Instant.now());
        return f;
    }

    @Test
    void subjectRef_roundTripsWhenSet() {
        SystemFinding saved = findings.save(held("alice", "character-part", "part-42")).block();
        assertThat(saved).isNotNull();

        SystemFinding read = findings.findById(saved.getId()).block();
        assertThat(read).isNotNull();
        assertThat(read.getSubjectRef()).isEqualTo("part-42");
        assertThat(read.getSurface()).isEqualTo("character-part");
        assertThat(read.getStatus()).isEqualTo("held");
    }

    @Test
    void subjectRef_isNullForAvatarPath() {
        // The existing avatar/profile finding path passes null → column reads back NULL.
        SystemFinding saved = findings.save(held("bob", "profile-avatar", null)).block();
        assertThat(saved).isNotNull();

        SystemFinding read = findings.findById(saved.getId()).block();
        assertThat(read).isNotNull();
        assertThat(read.getSubjectRef()).isNull();
        assertThat(read.getSurface()).isEqualTo("profile-avatar");
    }

    @Test
    void resolveLoad_carriesSubjectRefBack() {
        // The controller resolve() returns the loaded row → subjectRef is echoed back.
        // Prove the domain-pinned load path the service uses keeps subjectRef intact.
        SystemFinding saved = findings.save(held("carol", "character-part", "sticker-7")).block();
        assertThat(saved).isNotNull();

        StepVerifier.create(findings.findByIdAndDomain(saved.getId(), "default"))
                .assertNext(f -> assertThat(f.getSubjectRef()).isEqualTo("sticker-7"))
                .verifyComplete();
    }

    // ── resolved-reconcile query: only resolved+subjectRef'd rows of the surface, id-ASC ──

    private static SystemFinding row(String subject, String surface, String status,
                                     String subjectRef, String domain) {
        SystemFinding f = new SystemFinding();
        f.setReporter("@system");
        f.setSubject(subject);
        f.setSurface(surface);
        f.setDisposition("flagged");
        f.setStatus(status);
        f.setSubjectRef(subjectRef);
        f.setReviewer("actioned".equals(status) || "dismissed".equals(status) ? "mod-bob" : null);
        f.setDomain(domain);
        f.setTs(Instant.now());
        return f;
    }

    // @DataR2dbcTest shares ONE H2 db across the methods in this class (no per-test
    // rollback), so each reconcile test scopes to its OWN unique surface — the query's
    // `surface = :surface` predicate then isolates its rows from every other test's.

    @Test
    void resolvedForReconcile_returnsOnlyResolvedSubjectRefdRowsOfSurface_idAsc() {
        String surface = "recon-surface-only";
        // Wanted: two resolved rows WITH a subjectRef on THIS surface.
        Long a = findings.save(row("u", surface, "actioned", "part-1", "default")).block().getId();
        Long b = findings.save(row("u", surface, "dismissed", "part-2", "default")).block().getId();
        // Excluded: still held; resolved-but-no-subjectRef; a DIFFERENT surface.
        findings.save(row("u", surface, "held", "part-3", "default")).block();
        findings.save(row("u", surface, "actioned", null, "default")).block();
        findings.save(row("u", "recon-surface-other", "actioned", "av-9", "default")).block();

        StepVerifier.create(findings.findResolvedForReconcile(surface, 0L, 200))
                .assertNext(f -> {
                    assertThat(f.getId()).isEqualTo(a);
                    assertThat(f.getStatus()).isEqualTo("actioned");
                    assertThat(f.getSubjectRef()).isEqualTo("part-1");
                })
                .assertNext(f -> {
                    assertThat(f.getId()).isEqualTo(b);          // id-ASC ordering
                    assertThat(f.getStatus()).isEqualTo("dismissed");
                    assertThat(f.getSubjectRef()).isEqualTo("part-2");
                })
                .verifyComplete();
    }

    @Test
    void resolvedForReconcile_sinceIdCursorExcludesLessOrEqual() {
        String surface = "recon-surface-cursor";
        Long a = findings.save(row("u", surface, "actioned", "p-1", "default")).block().getId();
        Long b = findings.save(row("u", surface, "actioned", "p-2", "default")).block().getId();

        // sinceId = a → strict id > a, so the first row is excluded, only b returns.
        StepVerifier.create(findings.findResolvedForReconcile(surface, a, 200))
                .assertNext(f -> assertThat(f.getId()).isEqualTo(b))
                .verifyComplete();

        // sinceId = b (the max) → empty (a re-poll at the watermark never re-emits).
        StepVerifier.create(findings.findResolvedForReconcile(surface, b, 200))
                .verifyComplete();
    }

    @Test
    void resolvedForReconcile_limitCapsThePage() {
        String surface = "recon-surface-limit";
        findings.save(row("u", surface, "actioned", "p-1", "default")).block();
        findings.save(row("u", surface, "actioned", "p-2", "default")).block();
        findings.save(row("u", surface, "actioned", "p-3", "default")).block();

        // LIMIT 2 → only the two lowest-id rows come back.
        StepVerifier.create(findings.findResolvedForReconcile(surface, 0L, 2))
                .expectNextCount(2)
                .verifyComplete();
    }

    @Test
    void resolvedForReconcileInDomain_isPinnedToTheDomain() {
        String surface = "recon-surface-domain";
        Long mine = findings.save(row("u", surface, "actioned", "p-1", "brand-a")).block().getId();
        findings.save(row("u", surface, "actioned", "p-2", "brand-b")).block();

        // Domain-pinned finder returns ONLY brand-a's resolved row.
        StepVerifier.create(findings.findResolvedForReconcileInDomain(surface, 0L, "brand-a", 200))
                .assertNext(f -> {
                    assertThat(f.getId()).isEqualTo(mine);
                    assertThat(f.getDomain()).isEqualTo("brand-a");
                })
                .verifyComplete();

        // The cross-domain finder sees BOTH brands' rows (platform reconciler view) —
        // scoped to this test's own surface so no other test's rows are counted.
        StepVerifier.create(findings.findResolvedForReconcile(surface, 0L, 200))
                .expectNextCount(2)
                .verifyComplete();
    }
}
