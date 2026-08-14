package net.hugmesh.federation.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI document metadata for the federation registry spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}. A programmatic
 * {@link OpenAPI} bean (not the {@code @OpenAPIDefinition} annotation) keeps the
 * GraalVM native hint surface minimal — mirrors admin-bff's OpenApiConfig.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI federationOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("hugmesh-federation-api")
                        .version("0.1.0")
                        .description("Dynamic federation registry + manifest API. Serves the runtime "
                                + "module-federation manifest (visibility + kill-switch filtered), owns "
                                + "federation_modules CRUD, per-user bundle storage (content-hash sync), "
                                + "and the moderation / override kill-switch surface."));
    }
}
