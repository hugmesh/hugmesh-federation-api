package net.hugmesh.federation.repository;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.federation.model.UsernameSkeleton;

/**
 * Reactive (R2DBC) store for {@code username_skeleton} — the confusable-skeleton
 * cache keyed on the natural username PK.
 *
 * <p>The availability check uses two finders:
 * <ul>
 *   <li>{@link #findBySkeleton} — the (a) EXACT-skeleton tier: an indexed equality
 *       lookup over the NON-unique {@code ix_username_skeleton_skel} index. This is
 *       the homoglyph / leet collision ({@code adm1n} and {@code admin} share a
 *       skeleton), bounded regardless of namespace size.</li>
 *   <li>{@link #findBySkeletonFirstBucket} — a BOUNDED bucket scan for the optional
 *       user-vs-user edit sweep. Buckets by the skeleton's first char and caps the
 *       row count with {@code LIMIT}, so the cost stays bounded as the namespace
 *       grows (the design's transposition-stable-bucket + LIMIT requirement). The
 *       default policy is user-vs-user EQUALITY ONLY (collapse + the fold already
 *       absorb most typo-squats); this finder exists for a shadow/measured sweep.</li>
 * </ul>
 */
public interface UsernameSkeletonRepository extends ReactiveCrudRepository<UsernameSkeleton, String> {

    /**
     * Bounded bucket-scan SQL backing {@link #findBySkeletonFirstBucket}. Held as a
     * {@code static final String} constant per the data-access standard (no inline
     * {@code @Query} literals): derivation cannot express the parameterized
     * {@code LIMIT :limit}, so an explicit {@code @Query} is required — but the SQL
     * text is named here rather than inlined on the method annotation. Behaviour is
     * unchanged: same projection, same {@code skeleton_first = :first} predicate,
     * same {@code LIMIT :limit}.
     */
    String FIND_BY_SKELETON_FIRST_BUCKET =
            "SELECT * FROM username_skeleton WHERE skeleton_first = :first LIMIT :limit";

    /** (a) EXACT skeleton match — homoglyph/leet collision, indexed equality. */
    Flux<UsernameSkeleton> findBySkeleton(String skeleton);

    /** The owner of a username (EXACT username), for the self-exclusion-by-exact-username
     *  rule (a different-but-confusable owner stays flagged). */
    Mono<UsernameSkeleton> findByUsername(String username);

    /**
     * BOUNDED bucket scan for the user-vs-user edit sweep: every row whose skeleton
     * starts with the given char, capped at {@code limit}. Bucketed + LIMITed so the
     * sweep cost never scales with the whole namespace.
     */
    @Query(FIND_BY_SKELETON_FIRST_BUCKET)
    Flux<UsernameSkeleton> findBySkeletonFirstBucket(@Param("first") String first, @Param("limit") int limit);
}
