package systems.snapdragon.federation.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import systems.snapdragon.federation.model.FederationManifestDto;
import systems.snapdragon.federation.model.FederationModule;
import systems.snapdragon.federation.model.FederationOverride;
import systems.snapdragon.federation.model.ModerationRequest;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.service.OverrideService;

/**
 * GraalVM native-image / AOT reachability hints for the JSON-bound DTOs +
 * R2DBC-mapped entities reached reflectively (Jackson + Spring Data), and the
 * Swagger UI webjar resources native-image strips by default. Mirrors admin-bff's
 * NativeHintsConfig.
 *
 * <p>Best-effort: a full {@code -Pnative native:compile} on a GraalVM host is the
 * authoritative check; the parent's {@code native} profile (add-reachability-
 * metadata) supplies the library-side metadata for the Netty / Jackson / r2dbc /
 * cassandra-driver jars on top of these app-specific hints.
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(NativeHintsConfig.Hints.class)
public class NativeHintsConfig {

    static class Hints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection()
                    .registerType(FederationModule.class, dtoCategories())
                    .registerType(UserModule.class, dtoCategories())
                    .registerType(ModerationRequest.class, dtoCategories())
                    .registerType(FederationOverride.class, dtoCategories())
                    .registerType(FederationManifestDto.class, dtoCategories())
                    .registerType(FederationManifestDto.FederationRemoteDto.class, dtoCategories());

            // Resilience4j @CircuitBreaker advised bean: the account-states
            // profile-ban write path (OverrideService.applyUserScope /
            // clearScopeBySource) is wrapped in @CircuitBreaker, so keep the
            // advised target's constructors + methods reachable for the AOT proxy.
            hints.reflection()
                    .registerType(OverrideService.class, proxyTargetCategories());

            // Swagger UI static assets shipped inside the springdoc webflux-ui
            // starter's webjar; native-image drops classpath resources unless
            // explicitly included. The /v3/api-docs JSON is bean-produced and
            // unaffected.
            hints.resources()
                    .registerPattern("META-INF/resources/webjars/swagger-ui/*")
                    .registerPattern("META-INF/resources/webjars/swagger-ui/**");
        }

        private static MemberCategory[] dtoCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
                    MemberCategory.ACCESS_DECLARED_FIELDS,
            };
        }

        /** Constructors + methods for a Resilience4j-advised bean's AOT proxy. */
        private static MemberCategory[] proxyTargetCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
            };
        }
    }
}
