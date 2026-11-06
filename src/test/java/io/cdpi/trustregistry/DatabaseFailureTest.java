package io.cdpi.trustregistry;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Starts the app against its OWN PostgreSQL container, then stops that database and queries the endpoint.
 * A technical failure must be a 5xx problem document and must never contain an authorisation decision.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DatabaseFailureTest {

    static final PostgreSQLContainer<?> OWN_DB = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("inji_trust").withUsername("trust").withPassword("trust")
        .withInitScript("db/init/01-schema.sql");

    static {
        OWN_DB.start();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", OWN_DB::getJdbcUrl);
        r.add("spring.datasource.username", OWN_DB::getUsername);
        r.add("spring.datasource.password", OWN_DB::getPassword);
        r.add("spring.datasource.hikari.connection-timeout", () -> "1000");
        r.add("registry.admin.username", () -> "admin");
        r.add("registry.admin.password", () -> "test-admin-password-123");
    }

    @Autowired MockMvc mvc;

    @Test
    void databaseDown_returns503ProblemJson_neverAnAuthorisationDecision() throws Exception {
        OWN_DB.stop();

        mvc.perform(get("/v1/authorizations/check")
                .param("issuerId", "did:web:example.com:issuer").param("credentialType", "FarmerCredential"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.authorised").doesNotExist())
            .andExpect(jsonPath("$.reason").doesNotExist())
            .andExpect(content().string(not(containsStringIgnoringCase("jdbc"))))
            .andExpect(content().string(not(containsStringIgnoringCase("postgres"))))
            .andExpect(content().string(not(containsString(OWN_DB.getHost()))));
    }
}
