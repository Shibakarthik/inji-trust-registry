package io.cdpi.trustregistry.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import java.util.ArrayList;
import java.util.List;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    private static final String ADMIN_PATH_PREFIX = "/v1/admin/";
    private static final String ADMIN_HEADER_SCHEME = "adminRequestHeader";
    private static final String ADMIN_HEADER_NAME = "X-Registry-Admin-Request";

    @Bean
    OpenAPI trustRegistryOpenApi() {
        return new OpenAPI()
            .info(new Info()
                .title("Inji Trust Registry API")
                .version("v1")
                .description("""
                    Trust registry answering: is issuer X authorised to issue credential type Y?

                    **API version:** v1 (all paths are under `/v1`).

                    **Public read API (no authentication):** `GET /v1/authorizations/check`.
                    **Administration API:** HTTP Basic administrator credentials.
                    Admin write operations (POST, PUT, PATCH and DELETE) additionally require
                    the `X-Registry-Admin-Request: true` request header. Use the Authorize
                    dialog in Swagger UI to configure both schemes.

                    A technical failure is never reported as an authorisation decision: it is a 5xx error
                    and the response carries no `authorised` field.
                    """))
            .components(new Components()
                .addSecuritySchemes("basicAuth",
                    new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("basic")
                        .description("Registry administrator credentials (HTTP Basic)"))
                .addSecuritySchemes(ADMIN_HEADER_SCHEME,
                    new SecurityScheme().type(SecurityScheme.Type.APIKEY)
                        .in(SecurityScheme.In.HEADER)
                        .name(ADMIN_HEADER_NAME)
                        .description("Required with HTTP Basic for admin write operations; value: true")));
    }

    /**
     * Keep the OpenAPI contract aligned with SecurityConfig:
     * admin reads require Basic auth; admin writes require Basic auth AND the custom header.
     */
    @Bean
    OpenApiCustomizer adminRequestHeaderCustomizer() {
        return openApi -> openApi.getPaths().forEach((path, pathItem) -> {
            if (!path.startsWith(ADMIN_PATH_PREFIX)) {
                return;
            }

            pathItem.readOperationsMap().forEach((method, operation) -> {
                if (!isUnsafe(method)) {
                    return;
                }

                List<SecurityRequirement> requirements = operation.getSecurity();
                if (requirements == null || requirements.isEmpty()) {
                    requirements = new ArrayList<>();
                    requirements.add(new SecurityRequirement().addList("basicAuth"));
                    operation.setSecurity(requirements);
                }

                // Schemes in one SecurityRequirement are ANDed by OpenAPI.
                requirements.forEach(requirement -> requirement.addList(ADMIN_HEADER_SCHEME));
            });
        });
    }

    private boolean isUnsafe(PathItem.HttpMethod method) {
        return method == PathItem.HttpMethod.POST
            || method == PathItem.HttpMethod.PUT
            || method == PathItem.HttpMethod.PATCH
            || method == PathItem.HttpMethod.DELETE;
    }
}
