package net.hugmesh.federation.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.SequenceNode;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
 * goes away or stops running the suite.
 *
 * <p><b>The workflow is read as YAML, never as lines of text.</b> A first version looked for
 * lines that start with {@code if:}. {@code - if: false} as a step's first key,
 * {@code if : false}, {@code "if": false}, and the upload step's {@code if: failure()} moved
 * onto the suite step all switch the suite off, and all four passed. So the file is parsed
 * with SnakeYAML (the parser Spring Boot brings for {@code application.yml}) and every check
 * is on the parsed tree: a key is found however it is spelled and wherever it sits. Scalars
 * stay the text that was written, so YAML 1.1 cannot turn the key {@code on} into
 * {@code true}. A key that is not a scalar, the same key twice in one mapping, an anchor (so
 * also every alias) and a second document are refused: each lets a key be somewhere other
 * than where it reads. So is any character but printable ASCII and the newline (a look-alike
 * letter, a tab, an invisible line break). Comments are not part of the tree, so prose can
 * neither satisfy nor defeat a check.
 *
 * <p><b>Each level names what it may hold; nothing is found by a list of bad words.</b> A
 * list of forbidden flags is always one short ({@code JDK_JAVA_OPTIONS},
 * {@code shell: "true {0}"}, a matrix that expands to nothing). What is pinned:
 *
 * <ul>
 *   <li>the triggers are {@code pull_request} with nothing under it (no {@code branches},
 *       {@code paths} or {@code types} filter; never {@code pull_request_target}, which would
 *       hand a fork's code the repository's secrets) and {@code push} to {@code main} and
 *       {@code release/**} with no filter either;</li>
 *   <li>the workflow has no {@code env} and no {@code defaults}, and exactly one job,
 *       {@code test}, whose keys are {@code name}, {@code runs-on}, {@code timeout-minutes}
 *       (a literal number, ten or more) and {@code steps}: no {@code if},
 *       {@code continue-on-error}, {@code strategy}, {@code needs}, {@code env},
 *       {@code defaults}, {@code container} or {@code permissions};</li>
 *   <li>the fourth step is the suite, found by what it runs and not by its name. It has a
 *       name, the four environment values and exactly {@code ./mvnw -B -s
 *       .github/maven-ci-settings.xml verify -DskipITs}: no {@code if}, {@code shell} or
 *       {@code continue-on-error}, no extra flag, no extra variable;</li>
 *   <li>the three steps before it are the checkout (no {@code ref}), the JDK and the secret
 *       check, each pinned whole but for its name: a step in front of the suite reaches it
 *       through {@code $GITHUB_ENV}, {@code .mvn/maven.config} or the commit it checks
 *       out;</li>
 *   <li>an {@code if} may appear once in the file, as the report upload's {@code failure()}
 *       on the step after the suite, and {@code continue-on-error} appears nowhere;</li>
 *   <li>the job is on a literal {@code ubuntu-latest}: the repository is public and a fork's
 *       pull request runs this file, so it never names a self-hosted runner or reads
 *       {@code vars.RUNS_ON*}; the token is read-only;</li>
 *   <li>Maven resolves the {@code net.hugmesh} libraries through
 *       {@code .github/maven-ci-settings.xml} with {@code PACKAGES_READ_TOKEN}, as
 *       {@code release.yml} does, and that settings file sets no property and activates only
 *       its own profile ({@code skipTests} there would switch the suite off on GitHub
 *       alone);</li>
 *   <li>a newer push cancels the older run of the same pull request only: a push to
 *       {@code main} or {@code release/X.Y} is keyed by its commit and always finishes;</li>
 *   <li>no OTHER workflow runs on a pull request: a second one would be untested by this
 *       class.</li>
 * </ul>
 *
 * <p><b>What this cannot see.</b> It reads {@code ci.yml} and the settings file. It does not
 * read what {@code pom.xml}, {@code ./mvnw}, {@code .mvn/} or a
 * {@code junit-platform.properties} do with the command. And it runs only where the suite
 * runs: a pull request that switches the suite off in {@code ci.yml} also switches this test
 * off on GitHub for that pull request. Such a change is red only for whoever runs the suite
 * elsewhere: a local {@code ./mvnw test}, or the GitLab {@code test:mvn} job.
 */
class CiSuiteWorkflowGuardTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final Path WORKFLOWS = ROOT.resolve(".github/workflows");
    private static final Path CI = WORKFLOWS.resolve("ci.yml");

    private static final String SUITE_COMMAND = "./mvnw -B -s .github/maven-ci-settings.xml verify -DskipITs";
    private static final String PACKAGES_TOKEN = "${{ secrets.PACKAGES_READ_TOKEN }}";
    private static final String PACKAGES_ACTOR = "${{ secrets.PACKAGES_READ_ACTOR || github.actor }}";

    @Test
    @DisplayName("ci.yml runs on every pull_request and on a push to main and release/**: no filter, no other trigger")
    void ciRunsOnPullRequestsAndMain() throws IOException {
        Map<String, Object> on = map(ci().get("on"), "on");
        assertThat(on.keySet())
                .as("the triggers; pull_request_target would hand a fork's code the repository's secrets")
                .containsExactlyInAnyOrder("pull_request", "push");
        assertThat(on.get("pull_request"))
                .as("`pull_request:` with nothing under it: a branches, paths or types filter lets a pull"
                        + " request merge without the suite ever running on it")
                .isEqualTo("");
        assertThat(on.get("push"))
                .as("push names main and release/** and nothing else: a paths filter would skip the run of a merge")
                .isEqualTo(Map.of("branches", List.of("main", "release/**")));
    }

    @Test
    @DisplayName("ci.yml: one job, its fourth step runs exactly ./mvnw ... verify -DskipITs, and nothing can skip, soften or redirect it")
    void ciRunsTheWholeSuite() throws IOException {
        Map<String, Object> ci = ci();
        assertThat(ci.keySet())
                .as("top-level keys: a workflow `env` or `defaults` reaches every step (a -D in JDK_JAVA_OPTIONS,"
                        + " a `shell` that never runs the command)")
                .containsExactlyInAnyOrder("name", "on", "permissions", "concurrency", "jobs");
        Map<String, Object> jobs = map(ci.get("jobs"), "jobs");
        assertThat(jobs.keySet())
                .as("one job: a second one could hold the suite and never run, or be what the first one waits for")
                .containsExactly("test");
        Map<String, Object> job = map(jobs.get("test"), "jobs.test");
        assertThat(job.keySet())
                .as("jobs.test: an `if`, `continue-on-error`, `strategy` (a matrix that expands to nothing), `needs`,"
                        + " `env`, `defaults`, `container` or `permissions` here skips the suite, softens it or changes"
                        + " what the command means")
                .containsExactlyInAnyOrder("name", "runs-on", "timeout-minutes", "steps");
        assertThat(String.valueOf(job.get("timeout-minutes")))
                .as("a literal number of minutes, ten or more: an expression or a tiny value would cancel the job"
                        + " before the suite can report, and a cancelled run is not a red one")
                .matches("[1-9][0-9]+");

        List<Map<String, Object>> steps = new ArrayList<>();
        for (Object step : list(job.get("steps"), "jobs.test.steps")) {
            steps.add(map(step, "jobs.test.steps[" + steps.size() + "]"));
        }
        List<Integer> maven = new ArrayList<>();
        for (int i = 0; i < steps.size(); i++) {
            if (String.valueOf(steps.get(i).get("run")).contains("mvn")) {
                maven.add(i);
            }
        }
        assertThat(maven)
                .as("the suite is the one step that runs Maven, whatever it is called, and it is the fourth step")
                .containsExactly(3);

        // Everything in front of the suite can reach it: $GITHUB_ENV, .mvn/maven.config, the commit
        // that is checked out. So the three steps there are pinned whole (their names are free).
        assertThat(unnamed(steps.get(0)))
                .as("step 1 is the checkout with no input: a `ref` would test another commit than the pull request's")
                .isEqualTo(Map.of("uses", "actions/checkout@v4"));
        assertThat(unnamed(steps.get(1)))
                .as("step 2 installs Temurin 25 and nothing else")
                .isEqualTo(Map.of("uses", "actions/setup-java@v4",
                        "with", Map.of("distribution", "temurin", "java-version", "25", "cache", "maven")));
        Map<String, Object> secretCheck = unnamed(steps.get(2));
        assertThat(secretCheck.keySet()).as("step 3, the secret check, has an env and a script").containsExactlyInAnyOrder("env", "run");
        assertThat(secretCheck.get("env")).isEqualTo(Map.of("UPSTREAM_PACKAGES_TOKEN", PACKAGES_TOKEN));
        List<String> script = String.valueOf(secretCheck.get("run")).lines().map(String::strip).toList();
        assertThat(script)
                .as("the secret check is four lines: the test, one ::error:: message, `exit 1`, `fi`")
                .hasSize(4);
        assertThat(script.get(0)).isEqualTo("if [ -z \"${UPSTREAM_PACKAGES_TOKEN}\" ]; then");
        assertThat(script.get(1))
                .as("the message is one quoted string: no quote, $, backtick or backslash in it, nothing after it")
                .matches("echo \"::error::[^\"$`\\\\]+\"");
        assertThat(script.subList(2, 4)).containsExactly("exit 1", "fi");

        Map<String, Object> suite = steps.get(3);
        assertThat(suite.keySet())
                .as("the suite step is a name, an env and the command: an `if`, `continue-on-error`, `shell` or"
                        + " `working-directory` here skips it, softens it or runs something else")
                .containsExactlyInAnyOrder("name", "env", "run");
        assertThat(suite.get("run"))
                .as("exactly this command: the whole surefire suite, no `|| true`, no flag that skips or narrows it")
                .isEqualTo(SUITE_COMMAND);
        assertThat(suite.get("env"))
                .as("the suite's environment: a -D in MAVEN_OPTS, MAVEN_ARGS, JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS or"
                        + " _JAVA_OPTIONS reaches Maven or the test JVM like a flag on the command would")
                .isEqualTo(Map.of(
                        "UPSTREAM_PACKAGES_ACTOR", PACKAGES_ACTOR,
                        "UPSTREAM_PACKAGES_TOKEN", PACKAGES_TOKEN,
                        "TESTCONTAINERS_RYUK_DISABLED", "true",
                        "MAVEN_OPTS", "-Dapi.version=1.43"));

        assertThat(everywhere(ci, "if"))
                .as("the file may hold one `if`: failure(), on the step after the suite (the report upload)")
                .isSubsetOf("jobs.test.steps[4].if: failure()");
        assertThat(everywhere(ci, "continue-on-error")).as("nothing in the file fails softly").isEmpty();
    }

    @Test
    @DisplayName("ci.yml stays on a literal ubuntu-latest with a read-only token; no self-hosted label, no vars.RUNS_ON*")
    void ciStaysOnHostedRunners() throws IOException {
        Map<String, Object> ci = ci();
        Map<String, Object> jobs = map(ci.get("jobs"), "jobs");
        assertThat(jobs).as("jobs").isNotEmpty();
        jobs.forEach((id, job) -> assertThat(map(job, "jobs." + id).get("runs-on"))
                .as("jobs.%s.runs-on is one literal hosted label: not a list, not an expression", id)
                .isEqualTo("ubuntu-latest"));
        assertThat(strings(ci))
                .as("no key or value names a self-hosted runner or the org's runner variables")
                .noneMatch(s -> s.contains("self-hosted") || s.contains("vars.RUNS_ON"));
        assertThat(ci.get("permissions")).as("read-only token").isEqualTo(Map.of("contents", "read"));
        assertThat(everywhere(ci, "permissions")).as("and no job widens it").hasSize(1);
    }

    @Test
    @DisplayName("ci.yml reads net.hugmesh from GitHub Packages with PACKAGES_READ_TOKEN, no GITHUB_TOKEN fall-back")
    void ciUsesTheGitHubPackagesContract() throws IOException {
        Map<String, Object> ci = ci();
        assertThat(everywhere(ci, "UPSTREAM_PACKAGES_TOKEN"))
                .as("the secret check and the suite both read the package token from the repository secret")
                .containsExactly(
                        "jobs.test.steps[2].env.UPSTREAM_PACKAGES_TOKEN: " + PACKAGES_TOKEN,
                        "jobs.test.steps[3].env.UPSTREAM_PACKAGES_TOKEN: " + PACKAGES_TOKEN);
        assertThat(everywhere(ci, "UPSTREAM_PACKAGES_ACTOR"))
                .containsExactly("jobs.test.steps[3].env.UPSTREAM_PACKAGES_ACTOR: " + PACKAGES_ACTOR);
        assertThat(strings(ci))
                .as("GITHUB_TOKEN cannot read another repository's packages: a fall-back to it only turns"
                        + " `secret not set` into an opaque 401 deep in dependency resolution")
                .noneMatch(s -> s.contains("GITHUB_TOKEN"));
    }

    @Test
    @DisplayName(".github/maven-ci-settings.xml sets no property and activates only its own profile")
    void ciSettingsCannotSwitchTheSuiteOff() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document settings = factory.newDocumentBuilder().parse(ROOT.resolve(".github/maven-ci-settings.xml").toFile());
        assertThat(settings.getElementsByTagName("properties").getLength())
                .as("the suite command passes this file with -s. A <properties> in it (skipTests, maven.test.skip,"
                        + " groups) would reach surefire on GitHub and nowhere else")
                .isZero();
        List<String> active = new ArrayList<>();
        NodeList names = settings.getElementsByTagName("activeProfile");
        for (int i = 0; i < names.getLength(); i++) {
            active.add(names.item(i).getTextContent().trim());
        }
        assertThat(active)
                .as("the only active profile is the file's own repositories profile: naming a pom.xml profile"
                        + " here would switch it on for GitHub alone")
                .containsExactly("github-hugmesh-packages");
        assertThat(settings.getElementsByTagName("activation").getLength()).as("no profile activates itself").isZero();
    }

    @Test
    @DisplayName("ci.yml cancels only the older run of the same pull request; a push to main or release/** always finishes")
    void ciKeepsEveryPushRun() throws IOException {
        assertThat(ci().get("concurrency"))
                .as("one group per pull request, one per pushed commit: with a group per branch, two quick merges"
                        + " would cancel the first commit's run and leave that commit with no result")
                .isEqualTo(Map.of(
                        "group", "ci-${{ github.ref }}-${{ github.event_name == 'pull_request' && 'pr' || github.sha }}",
                        "cancel-in-progress", "true"));
    }

    @Test
    @DisplayName("ci.yml is the only workflow a pull request starts")
    void noOtherWorkflowRunsOnPullRequests() throws IOException {
        List<String> prWorkflows = new ArrayList<>();
        try (Stream<Path> files = Files.list(WORKFLOWS)) {
            for (Path wf : files.filter(p -> p.toString().matches(".*\\.ya?ml$")).sorted().toList()) {
                // `on` is one event, a list of events, or a mapping keyed by event
                Object on = workflow(wf).get("on");
                List<?> events = on instanceof Map<?, ?> byEvent ? List.copyOf(byEvent.keySet())
                        : on instanceof List<?> named ? named : List.of(String.valueOf(on));
                if (events.stream().anyMatch(event -> String.valueOf(event).contains("pull_request"))) {
                    prWorkflows.add(wf.getFileName().toString());
                }
            }
        }
        assertThat(prWorkflows).containsExactly("ci.yml");
    }

    private static Map<String, Object> ci() throws IOException {
        assertThat(CI).as(".github/workflows/ci.yml must exist: it is the only pre-merge run of this suite")
                .isRegularFile();
        assertThat(Files.readString(CI, StandardCharsets.UTF_8).chars()
                .filter(c -> c != '\n' && (c < ' ' || c > '~')).boxed().toList())
                .as("ci.yml is printable ASCII and newlines: a look-alike letter, a tab or an invisible line"
                        + " break is how a key hides from a reader, and YAML parsers disagree about them")
                .isEmpty();
        return workflow(CI);
    }

    /** A workflow file as a tree of {@link Map}, {@link List} and {@link String}. */
    private static Map<String, Object> workflow(Path file) throws IOException {
        String name = file.getFileName().toString();
        // compose() stops at the node graph: no YAML 1.1 typing, and it throws on a second document
        Node root = new Yaml(new LoaderOptions()).compose(new StringReader(Files.readString(file, StandardCharsets.UTF_8)));
        assertThat(root).as("%s holds a YAML document", name).isNotNull();
        return map(plain(root, name), name);
    }

    /**
     * A YAML node as a Map, a List or the String that was written ({@code on} stays "on",
     * {@code false} stays "false", an empty value is ""). Refuses what would let a key be
     * somewhere other than where it reads: a key that is not a scalar, the same key twice in
     * one mapping, and any anchor, which rules out every alias and every aliased merge.
     */
    private static Object plain(Node node, String at) {
        assertThat(node.getAnchor())
                .as("%s carries an anchor: with an alias or a merge, a key written once is in force elsewhere", at)
                .isNull();
        if (node instanceof ScalarNode scalar) {
            return scalar.getValue();
        }
        if (node instanceof SequenceNode sequence) {
            List<Object> items = new ArrayList<>();
            for (Node item : sequence.getValue()) {
                items.add(plain(item, at + "[" + items.size() + "]"));
            }
            return items;
        }
        Map<String, Object> entries = new LinkedHashMap<>();
        for (NodeTuple tuple : ((MappingNode) node).getValue()) {
            Node keyNode = tuple.getKeyNode();
            assertThat(keyNode).as("%s: every key is a scalar", at).isInstanceOf(ScalarNode.class);
            assertThat(keyNode.getAnchor()).as("%s: a key carries an anchor", at).isNull();
            String key = ((ScalarNode) keyNode).getValue();
            assertThat(entries).as("%s: `%s` is written twice in one mapping", at, key).doesNotContainKey(key);
            entries.put(key, plain(tuple.getValueNode(), at + "." + key));
        }
        return entries;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value, String what) {
        assertThat(value).as("%s must be a mapping", what).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value, String what) {
        assertThat(value).as("%s must be a list", what).isInstanceOf(List.class);
        return (List<Object>) value;
    }

    /** A step without its {@code name}: a name is a label and may say anything. */
    private static Map<String, Object> unnamed(Map<String, Object> step) {
        Map<String, Object> rest = new LinkedHashMap<>(step);
        rest.remove("name");
        return rest;
    }

    /** Every place {@code key} is written anywhere in the tree, as {@code path: value}. */
    private static List<String> everywhere(Object tree, String key) {
        List<String> found = new ArrayList<>();
        find(tree, key, "", found);
        return found;
    }

    private static void find(Object tree, String key, String path, List<String> found) {
        if (tree instanceof Map<?, ?> entries) {
            entries.forEach((name, value) -> {
                String here = path.isEmpty() ? String.valueOf(name) : path + "." + name;
                if (key.equals(name)) {
                    found.add(here + ": " + value);
                }
                find(value, key, here, found);
            });
        } else if (tree instanceof List<?> items) {
            for (int i = 0; i < items.size(); i++) {
                find(items.get(i), key, path + "[" + i + "]", found);
            }
        }
    }

    /** Every key and every scalar value in the tree. */
    private static List<String> strings(Object tree) {
        List<String> all = new ArrayList<>();
        addStrings(tree, all);
        return all;
    }

    private static void addStrings(Object tree, List<String> all) {
        if (tree instanceof Map<?, ?> entries) {
            entries.forEach((name, value) -> {
                all.add(String.valueOf(name));
                addStrings(value, all);
            });
        } else if (tree instanceof List<?> items) {
            items.forEach(item -> addStrings(item, all));
        } else {
            all.add(String.valueOf(tree));
        }
    }
}
