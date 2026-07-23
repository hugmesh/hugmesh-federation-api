package systems.hugmesh.federation.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ScopeKind} contract: the enum is a CODE-SIDE lens over the closed
 * {@code federation_override.scope} vocabulary, and its wire form is BYTE-IDENTICAL
 * to the prior lowercase {@code "all"/"user"/"role"} strings the system stored /
 * exchanged. These tests pin that equivalence so the enum can never silently drift
 * the DB/JSON value.
 */
class ScopeKindTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        // The stored/transmitted token is the lowercase form, NOT the Java constant name.
        assertThat(ScopeKind.ALL.value()).isEqualTo("all");
        assertThat(ScopeKind.USER.value()).isEqualTo("user");
        assertThat(ScopeKind.ROLE.value()).isEqualTo("role");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        // Order matters: ManifestService.SCOPE_KINDS derives the scope IN(...) list from
        // values(), and it must stay [all, user, role] (the prior List.of order).
        assertThat(java.util.Arrays.stream(ScopeKind.values()).map(ScopeKind::value).toList())
                .containsExactly("all", "user", "role");
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (ScopeKind k : ScopeKind.values()) {
            // value() -> fromWire() returns the SAME constant (round-trip identity).
            assertThat(ScopeKind.fromWire(k.value())).isEqualTo(k);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        // A null / unknown / wrong-case token maps to null (the read path treats null as
        // "matches nothing", exactly the prior string-equals fall-through behaviour).
        assertThat(ScopeKind.fromWire(null)).isNull();
        assertThat(ScopeKind.fromWire("")).isNull();
        assertThat(ScopeKind.fromWire("everything")).isNull();
        assertThat(ScopeKind.fromWire("ALL")).isNull();   // case-sensitive: the column is lowercase
        assertThat(ScopeKind.fromWire("All")).isNull();
    }

    @Test
    void isValid_acceptsOnlyTheThreeTokens() {
        assertThat(ScopeKind.isValid("all")).isTrue();
        assertThat(ScopeKind.isValid("user")).isTrue();
        assertThat(ScopeKind.isValid("role")).isTrue();
        // The legacy isScope() guard rejected anything else; isValid matches it.
        assertThat(ScopeKind.isValid("bogus")).isFalse();
        assertThat(ScopeKind.isValid(null)).isFalse();
        assertThat(ScopeKind.isValid("USER")).isFalse();
    }

    @Test
    void json_serializesToLowercaseToken() throws Exception {
        // @JsonValue => the enum serializes to its lowercase wire token, never "ALL".
        assertThat(MAPPER.writeValueAsString(ScopeKind.ALL)).isEqualTo("\"all\"");
        assertThat(MAPPER.writeValueAsString(ScopeKind.USER)).isEqualTo("\"user\"");
        assertThat(MAPPER.writeValueAsString(ScopeKind.ROLE)).isEqualTo("\"role\"");
    }

    @Test
    void json_deserializesFromLowercaseToken() throws Exception {
        // @JsonCreator(fromWire) => the lowercase token parses back to the constant.
        assertThat(MAPPER.readValue("\"all\"", ScopeKind.class)).isEqualTo(ScopeKind.ALL);
        assertThat(MAPPER.readValue("\"user\"", ScopeKind.class)).isEqualTo(ScopeKind.USER);
        assertThat(MAPPER.readValue("\"role\"", ScopeKind.class)).isEqualTo(ScopeKind.ROLE);
    }

    @Test
    void json_unknownTokenDeserializesToNull_neverThrows() throws Exception {
        // An unrecognised token is tolerated (null), mirroring the read-path leniency.
        assertThat(MAPPER.readValue("\"nope\"", ScopeKind.class)).isNull();
    }
}
