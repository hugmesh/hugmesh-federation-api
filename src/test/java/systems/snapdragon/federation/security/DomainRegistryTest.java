package systems.snapdragon.federation.security;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DomainRegistry} — the issuer -&gt; brand/domain source of truth and the
 * keystone of the federation-api multi-tenant isolation boundary: get this wrong and
 * a token from brand-Y is mapped to brand-X (or an untrusted Casdoor is accepted).
 * COPIED-converter sibling of {@code systems.snapdragon.gateway.security.DomainRegistry}
 * (the federation BFF is issuer-keyed only — no host fallback), so this mirrors the
 * gateway's {@code DomainRegistryTest} adjusted to the 2-arg constructor.
 *
 * <p>The adversarial verify flagged these FAIL-CLOSED branches as correct but
 * UNTESTED; this fills the gap. Delineated per the test standard:
 * <ul>
 *   <li>USER-SITUATIONAL — a single configured tenant (or no config) resolving its
 *       own issuer to {@code "default"}.</li>
 *   <li>MULTIUSER-SITUATIONAL — several brands configured, each resolving its own.</li>
 *   <li>CROSS-USER — the isolation boundary: brand-Y's issuer must NOT resolve to
 *       brand-X's domain, and an UNTRUSTED issuer FAILS CLOSED (null).</li>
 *   <li>CONCURRENT — many threads resolving issuers at once see consistent answers
 *       and an untrusted issuer is never fail-OPEN under load.</li>
 * </ul>
 */
class DomainRegistryTest {

    // ── USER-SITUATIONAL — single-tenant / legacy back-compat ────────────────────
    @Nested
    class UserSituational_SingleIssuer {

        @Test
        void noConfigAtAll_anyIssuer_mapsToDefaultUnconditionally() {
            // The most degenerate single-tenant case: no issuer-uri, no registry.
            // The map is EMPTY so domainOf(...) returns "default" for ANY issuer
            // (including null) — single-issuer back-compat.
            DomainRegistry reg = new DomainRegistry("", "");
            assertThat(reg.domainOf("http://anything:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf(null)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf("")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.isMultiIssuer()).isFalse();
        }

        @Test
        void loneConfiguredIssuer_mapsToDefault_trailingSlashTolerant() {
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000/", "");
            // a trailing slash on either side is normalised away
            assertThat(reg.domainOf("http://casdoor:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf("http://casdoor:8000/")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.isTrusted("http://casdoor:8000")).isTrue();
            // exactly the lone back-compat entry => NOT multi-issuer (the swap gate).
            assertThat(reg.isMultiIssuer()).isFalse();
        }

        @Test
        void singleIssuer_theConfiguredIssuer_isDefault_aDifferentIssuerFailsClosed() {
            // With exactly the ONE configured issuer seeded, that issuer -> default.
            // A DIFFERENT issuer (which the single-issuer resource server would already
            // reject at iss-validation) returns null defensively — it is never silently
            // mapped to "default". Only the EMPTY-map case (no issuer-uri at all)
            // returns "default" for any issuer.
            DomainRegistry reg = new DomainRegistry("http://casdoor:8000", "");
            assertThat(reg.domainOf("http://casdoor:8000")).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(reg.domainOf("http://someone-else:8000")).isNull();
            assertThat(reg.isTrusted("http://someone-else:8000")).isFalse();
        }
    }

    // ── MULTIUSER-SITUATIONAL — several brands, each its own ─────────────────────
    @Nested
    class MultiUserSituational_MultiBrand {

        private final DomainRegistry reg = new DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy");

        @Test
        void eachBrandIssuerResolvesToItsOwnDomain() {
            assertThat(reg.domainOf("https://id.brandx.tld")).isEqualTo("brandx");
            assertThat(reg.domainOf("https://id.brandy.tld")).isEqualTo("brandy");
            assertThat(reg.isMultiIssuer()).isTrue();
            assertThat(reg.trustedIssuers())
                    .containsExactlyInAnyOrder("https://id.brandx.tld", "https://id.brandy.tld");
        }

        @Test
        void isMultiIssuer_trueOnlyWhenMoreThanOneIssuer() {
            // The swap gate: a single-pair registry is NOT multi-issuer even though it
            // came from the CSV; >1 trusted issuer is the boundary.
            DomainRegistry one = new DomainRegistry("", "https://id.a.tld=a");
            assertThat(one.isMultiIssuer()).isFalse();
            DomainRegistry two = new DomainRegistry("", "https://id.a.tld=a,https://id.b.tld=b");
            assertThat(two.isMultiIssuer()).isTrue();
        }
    }

    // ── CROSS-USER — the isolation boundary (the security keystone) ──────────────
    @Nested
    class CrossUser_IsolationBoundary {

        private final DomainRegistry reg = new DomainRegistry(
                "https://id.brandx.tld",
                "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy");

        @Test
        void brandYIssuer_doesNotResolveToBrandXDomain() {
            // NEGATIVE isolation: brand-Y's issuer must never come back as brand-X.
            assertThat(reg.domainOf("https://id.brandy.tld")).isNotEqualTo("brandx");
            assertThat(reg.domainOf("https://id.brandx.tld")).isNotEqualTo("brandy");
        }

        @Test
        void untrustedIssuer_inMultiBrand_failsClosed_null() {
            // An issuer NOT in the multi-brand allowlist must be rejected (null), never
            // silently mapped to some domain — this is what makes the multi-issuer
            // decoder 401 an unknown iss (and any in-process caller fail closed).
            assertThat(reg.domainOf("https://evil.attacker.tld")).isNull();
            assertThat(reg.isTrusted("https://evil.attacker.tld")).isFalse();
        }

        @Test
        void nullIssuer_inMultiBrand_failsClosed_null() {
            assertThat(reg.domainOf(null)).isNull();
            assertThat(reg.isTrusted(null)).isFalse();
        }
    }

    // ── sanitize() — the NO_DOMAIN sentinel can NEVER be a real domain ───────────
    @Nested
    class Sanitize_RegexPin {

        @Test
        void domainValueIsSanitisedToLowerAlnumHyphenOnly() {
            // Mirrors the gateway test: every non-[a-z0-9-] char becomes a hyphen and
            // the value is lower-cased.
            DomainRegistry r = new DomainRegistry("",
                    "https://id.a.tld=Brand_X!!,https://id.b.tld=BRAND B");
            assertThat(r.domainOf("https://id.a.tld")).isEqualTo("brand-x--");
            assertThat(r.domainOf("https://id.b.tld")).isEqualTo("brand-b");
        }

        @Test
        void sanitisedDomain_canNeverEqualTheNoDomainSentinel() {
            // The fail-closed sentinel DomainScope.NO_DOMAIN begins with a SPACE
            // (" no-domain"); sanitize() yields ONLY [a-z0-9-], so a configured domain
            // value can never collide with the sentinel — even one literally spelled
            // "no-domain" with spaces. Pin both the regex AND the sentinel relationship.
            String spacey = " no-domain";        // exactly the sentinel string
            DomainRegistry r = new DomainRegistry("",
                    "https://id.s.tld=" + spacey.replace(" ", "_") + ",https://id.t.tld=No Domain");
            String s = r.domainOf("https://id.s.tld");
            String t = r.domainOf("https://id.t.tld");
            // Every produced domain matches the pinned charset and contains no space.
            assertThat(s).matches("[a-z0-9-]+");
            assertThat(t).matches("[a-z0-9-]+");
            assertThat(s).doesNotContain(" ");
            assertThat(t).doesNotContain(" ");
            // ...and therefore is NOT the sentinel a domain-pinned finder excludes.
            assertThat(s).isNotEqualTo(DomainScope.NO_DOMAIN);
            assertThat(t).isNotEqualTo(DomainScope.NO_DOMAIN);
            assertThat(DomainScope.NO_DOMAIN).doesNotMatch("[a-z0-9-]+");
        }
    }

    // ── CONCURRENT — many threads resolving at once ──────────────────────────────
    @Nested
    class Concurrent {

        @Test
        void concurrentResolution_isConsistent_andUntrustedAlwaysFailsClosed() throws Exception {
            DomainRegistry reg = new DomainRegistry(
                    "https://id.brandx.tld",
                    "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy");
            ExecutorService pool = Executors.newFixedThreadPool(8);
            AtomicBoolean mismatch = new AtomicBoolean(false);
            try {
                Future<?>[] futures = new Future<?>[200];
                for (int i = 0; i < futures.length; i++) {
                    final boolean x = (i % 2 == 0);
                    futures[i] = pool.submit(() -> {
                        String iss = x ? "https://id.brandx.tld" : "https://id.brandy.tld";
                        String expect = x ? "brandx" : "brandy";
                        for (int k = 0; k < 500; k++) {
                            if (!expect.equals(reg.domainOf(iss))) mismatch.set(true);
                            // an untrusted issuer must ALWAYS fail closed under load
                            if (reg.domainOf("https://evil.tld") != null) mismatch.set(true);
                        }
                    });
                }
                for (Future<?> f : futures) f.get(30, TimeUnit.SECONDS);
            } finally {
                pool.shutdownNow();
            }
            assertThat(mismatch.get())
                    .as("no cross-brand or fail-open mismatch under concurrency").isFalse();
        }
    }
}
