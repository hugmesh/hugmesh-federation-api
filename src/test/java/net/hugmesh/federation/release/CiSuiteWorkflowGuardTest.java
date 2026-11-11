package net.hugmesh.federation.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins {@code .github/workflows/ci.yml}: the one GitHub workflow that runs this suite before
 * a merge.
 *
 * <p>Release PR #20 bumped {@code pom.xml} to 0.4.0-beta.2 and left README.md behind, so
 * {@code ReadmeFactsGuardTest} went red on main. Nothing on GitHub noticed: the only workflow
 * was {@code release.yml}, whose image build runs {@code package -DskipTests}, and the
 * release went green on the red commit. This test fails if the workflow that closes that gap
 * goes away or stops running the suite:
 *
 * <ul>
 *   <li>it runs on {@code pull_request} (never {@code pull_request_target}, which would hand
 *       a fork's code the repository's secrets) and on a push to {@code main};</li>
 *   <li>a step runs {@code ./mvnw ... verify} (the surefire suite) and nothing in the file
 *       skips tests ({@code -DskipTests}, {@code -Dmaven.test.skip}, {@code -Dtest=} narrowing,
 *       {@code continue-on-error});</li>
 *   <li>every job is on a literal {@code ubuntu-latest}: the repository is public and a fork's
 *       pull request runs this file, so it never names a self-hosted runner or reads
 *       {@code vars.RUNS_ON*};</li>
 *   <li>Maven resolves the {@code net.hugmesh} libraries through
 *       {@code .github/maven-ci-settings.xml} with {@code PACKAGES_READ_TOKEN}, as
 *       {@code release.yml} does;</li>
 *   <li>no OTHER workflow runs on a pull request: a second one would be untested by this
 *       class.</li>
 * </ul>
 *
 * <p>Whole-line comments are stripped first, so prose about a flag can neither satisfy nor
 * defeat a check.
 */
class CiSuiteWorkflowGuardTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final Path WORKFLOWS = ROOT.resolve(".github/workflows");
    private static final Path CI = WORKFLOWS.resolve("ci.yml");

    @Test
    @DisplayName("ci.yml runs on pull_request and on a push to main, never on pull_request_target")
    void ciRunsOnPullRequestsAndMain() throws IOException {
        String on = topLevelBlock(ci(), "on");
        assertThat(Pattern.compile("(?m)^\\s+pull_request:").matcher(on).find())
                .as("the `on:` block must name pull_request").isTrue();
        assertThat(on).as("pull_request_target hands a fork's code the secrets")
                .doesNotContain("pull_request_target");
        assertThat(Pattern.compile("(?m)^\\s+push:\\s*\\n\\s+branches:\\s*\\[main\\b").matcher(on).find())
                .as("the `on:` block must push-trigger main").isTrue();
    }

    @Test
    @DisplayName("ci.yml runs ./mvnw verify and nothing skips or narrows the suite")
    void ciRunsTheWholeSuite() throws IOException {
        String yaml = ci();
        assertThat(Pattern.compile("(?m)^\\s+run:\\s*\\./mvnw\\s+-B\\s+-s\\s+\\.github/maven-ci-settings\\.xml\\s+verify\\b")
                .matcher(yaml).find())
                .as("a step must run `./mvnw -B -s .github/maven-ci-settings.xml verify`")
                .isTrue();
        assertThat(yaml)
                .as("nothing may skip, narrow or soften the suite")
                .doesNotContain("skipTests")
                .doesNotContain("maven.test.skip")
                .doesNotContain("maven.test.failure.ignore")
                .doesNotContain("-Dtest=")
                .doesNotContain("continue-on-error");
    }

    @Test
    @DisplayName("every ci.yml job is on a literal ubuntu-latest; no self-hosted label, no vars.RUNS_ON*")
    void ciStaysOnHostedRunners() throws IOException {
        String yaml = ci();
        List<String> runsOn = yaml.lines().map(String::strip).filter(l -> l.startsWith("runs-on:")).toList();
        assertThat(runsOn).as("runs-on lines").isNotEmpty().allMatch("runs-on: ubuntu-latest"::equals);
        assertThat(yaml).doesNotContain("self-hosted").doesNotContain("vars.RUNS_ON");
        assertThat(topLevelBlock(yaml, "permissions")).as("read-only token").contains("contents: read")
                .doesNotContain("write");
    }

    @Test
    @DisplayName("ci.yml reads net.hugmesh from GitHub Packages with PACKAGES_READ_TOKEN, no GITHUB_TOKEN fall-back")
    void ciUsesTheGitHubPackagesContract() throws IOException {
        String yaml = ci();
        assertThat(yaml)
                .contains("UPSTREAM_PACKAGES_TOKEN: ${{ secrets.PACKAGES_READ_TOKEN }}")
                .contains("UPSTREAM_PACKAGES_ACTOR: ${{ secrets.PACKAGES_READ_ACTOR || github.actor }}")
                .doesNotContain("PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN");
    }

    @Test
    @DisplayName("ci.yml is the only workflow a pull request starts")
    void noOtherWorkflowRunsOnPullRequests() throws IOException {
        List<String> prWorkflows = new ArrayList<>();
        try (Stream<Path> files = Files.list(WORKFLOWS)) {
            for (Path wf : files.filter(p -> p.toString().matches(".*\\.ya?ml$")).sorted().toList()) {
                String on = topLevelBlock(code(Files.readString(wf, StandardCharsets.UTF_8)), "on");
                if (on.contains("pull_request")) {
                    prWorkflows.add(wf.getFileName().toString());
                }
            }
        }
        assertThat(prWorkflows).containsExactly("ci.yml");
    }

    private static String ci() throws IOException {
        assertThat(CI).as(".github/workflows/ci.yml must exist: it is the only pre-merge run of this suite")
                .isRegularFile();
        return code(Files.readString(CI, StandardCharsets.UTF_8));
    }

    /** The lines of a top-level YAML key's block (`key:` at column 0 up to the next column-0 key). */
    private static String topLevelBlock(String yaml, String key) {
        StringBuilder out = new StringBuilder();
        boolean in = false;
        for (String line : yaml.split("\n", -1)) {
            if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0))) {
                in = line.startsWith(key + ":");
            }
            if (in) {
                out.append(line).append('\n');
            }
        }
        assertThat(out).as("top-level `%s:` block", key).isNotEmpty();
        return out.toString();
    }

    /** Drops whole-line comments so prose cannot satisfy or defeat a check. */
    private static String code(String text) {
        StringBuilder out = new StringBuilder();
        for (String line : text.split("\n", -1)) {
            if (!line.stripLeading().startsWith("#")) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }
}
