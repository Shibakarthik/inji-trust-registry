package io.cdpi.trustregistry.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

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
                    **Administration API (HTTP Basic, administrator credentials):** `/v1/admin/**`.

                    A technical failure is never reported as an authorisation decision: it is a 5xx error
                    and the response carries no `authorised` field.
                    """))
            .components(new Components().addSecuritySchemes("basicAuth",
                new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("basic")
                    .description("Registry administrator credentials (HTTP Basic)")));
    }
}
