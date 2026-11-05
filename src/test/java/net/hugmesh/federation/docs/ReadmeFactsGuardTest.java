package net.hugmesh.federation.docs;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the facts in the repository docs that have gone stale before, against the files
 * they describe. A docs-only PR has no compiler; this is its test.
 *
 * <ul>
 *   <li><b>Versions.</b> The README names the parent POM version and the project version
 *       exactly as {@code pom.xml} declares them, and the {@code hugmesh-commons} version
 *       exactly as the jar on the test classpath carries it (the commons version is managed
 *       by the parent, not declared in this pom). The retired pins {@code 2.8.0} /
 *       {@code 2.1.0} must not come back: they were reintroduced once by a branch that
 *       predated the beta line.</li>
 *   <li><b>Retired brand host.</b> The module seeds were rebranded to {@code hugmesh-*}
 *       (PR #16), and {@code 039} / {@code 041} match the old host by SHAPE (a ten-character
 *       brand prefix) so the changelog never spells it. The docs must not spell it either.
 *       This test uses the same shape: ten lowercase letters, a dash, then a module UI host
 *       or the {@code -*} wildcard the old prose used.</li>
 *   <li><b>Changesets.</b> Every changelog file is mentioned in the README's schema
 *       section, either as {@code `NNN`} or inside a {@code `AAA`–`BBB`} range.</li>
 * </ul>
 *
 * <p>Reads the repository files directly (surefire runs with the project basedir as the
 * working directory), like {@code ReleaseImageGuardTest}.
 */
class ReadmeFactsGuardTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final List<String> DOCS =
            List.of("README.md", "SECURITY.md", "docs/testing/MULTI-ISSUER-SLICE.md");

    /** Ten lowercase letters, a dash, then a module UI host (or the old prose's {@code -*}). */
    private static final Pattern RETIRED_HOST_SHAPE = Pattern.compile(
            "\\b[a-z]{10}-(?:\\*|(?:forum|mastodon|matrix|games|wiki|mod|user|owncast|tube"
                    + "|character-forge|character-studio)-ui\\b|api-docs\\b)");

    private static final List<String> RETIRED_PINS = List.of(
            "hugmesh-parent:2.8.0", "hugmesh-commons:2.8.0", "hugmesh-commons:2.1.0", "(2.1.0");

    @Test
    @DisplayName("README names the parent and project versions exactly as pom.xml declares them")
    void readmeNamesThePomVersions() throws Exception {
        Document pom = parse(ROOT.resolve("pom.xml"));
        Element project = pom.getDocumentElement();
        String parentVersion = childText(childElement(project, "parent"), "version");
        String projectVersion = childText(project, "version");
        assertThat(parentVersion).isNotBlank();
        assertThat(projectVersion).isNotBlank();

        String readme = read("README.md");
        assertThat(readme)
                .as("README must name hugmesh-parent:%s", parentVersion)
                .contains("hugmesh-parent:" + parentVersion)
                .as("README's package line must name federation-%s.jar", projectVersion)
                .contains("federation-" + projectVersion + ".jar")
                .as("README's Releases section must name the current version")
                .contains("currently `" + projectVersion + "`");
    }

    @Test
    @DisplayName("README names the hugmesh-commons version the test classpath resolves")
    void readmeNamesTheCommonsVersionOnTheClasspath() throws IOException {
        Properties props = new Properties();
        try (InputStream in = ReadmeFactsGuardTest.class.getResourceAsStream(
                "/META-INF/maven/net.hugmesh/hugmesh-commons/pom.properties")) {
            assertThat(in).as("hugmesh-commons pom.properties on the test classpath").isNotNull();
            props.load(in);
        }
        String commonsVersion = props.getProperty("version");
        assertThat(commonsVersion).isNotBlank();
        assertThat(read("README.md"))
                .as("README must name hugmesh-commons:%s", commonsVersion)
                .contains("hugmesh-commons:" + commonsVersion);
    }

    @Test
    @DisplayName("README carries none of the retired 2.8.0 / 2.1.0 pins")
    void readmeCarriesNoRetiredPins() throws IOException {
        String readme = read("README.md");
        for (String pin : RETIRED_PINS) {
            assertThat(readme).as("retired pin %s", pin).doesNotContain(pin);
        }
    }

    @Test
    @DisplayName("No doc spells the retired brand's Service host (ten-letter prefix shape)")
    void docsNeverSpellTheRetiredBrandHost() throws IOException {
        for (String doc : DOCS) {
            Matcher m = RETIRED_HOST_SHAPE.matcher(read(doc));
            List<String> hits = new ArrayList<>();
            while (m.find()) {
                hits.add(m.group());
            }
            assertThat(hits).as("%s names a host of the retired brand's shape", doc).isEmpty();
        }
    }

    @Test
    @DisplayName("Every changelog file is mentioned in the README schema section")
    void readmeMentionsEveryChangeset() throws IOException {
        String readme = read("README.md");
        TreeSet<Integer> mentioned = new TreeSet<>();
        Matcher single = Pattern.compile("`(\\d{3})`").matcher(readme);
        while (single.find()) {
            mentioned.add(Integer.parseInt(single.group(1)));
        }
        Matcher range = Pattern.compile("`(\\d{3})`\\s*[–-]\\s*`(\\d{3})`").matcher(readme);
        while (range.find()) {
            int from = Integer.parseInt(range.group(1));
            int to = Integer.parseInt(range.group(2));
            for (int n = from; n <= to; n++) {
                mentioned.add(n);
            }
        }
        List<String> missing = new ArrayList<>();
        try (Stream<Path> files = Files.list(ROOT.resolve("src/main/resources/db/changelog"))) {
            files.map(p -> p.getFileName().toString())
                    .filter(n -> n.matches("\\d{3}-.*\\.xml"))
                    .sorted()
                    .forEach(n -> {
                        int number = Integer.parseInt(n.substring(0, 3));
                        if (!mentioned.contains(number)) {
                            missing.add(n);
                        }
                    });
        }
        assertThat(missing).as("changelog files the README never mentions").isEmpty();
    }

    private static String read(String relative) throws IOException {
        return Files.readString(ROOT.resolve(relative), StandardCharsets.UTF_8);
    }

    private static Document parse(Path xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setNamespaceAware(false);
        return f.newDocumentBuilder().parse(xml.toFile());
    }

    private static Element childElement(Element parent, String name) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node instanceof Element e && name.equals(e.getTagName())) {
                return e;
            }
        }
        throw new AssertionError("<" + name + "> missing under <" + parent.getTagName() + ">");
    }

    private static String childText(Element parent, String name) {
        return childElement(parent, name).getTextContent().trim();
    }
}
