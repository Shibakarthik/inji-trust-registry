package io.cdpi.trustregistry;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Full application context against a real PostgreSQL (Testcontainers; requires a running Docker daemon).
 * The container is initialised with the same db/init/01-schema.sql used in deployment.
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class AbstractPostgresTest {

    public static final String ADMIN_USER = "admin";
    public static final String ADMIN_PASSWORD = "test-admin-password-123";

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("inji_trust").withUsername("trust").withPassword("trust")
        .withInitScript("db/init/01-schema.sql");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", POSTGRES::getUsername);
        r.add("spring.datasource.password", POSTGRES::getPassword);
        r.add("registry.admin.username", () -> ADMIN_USER);
        r.add("registry.admin.password", () -> ADMIN_PASSWORD);
    }

    @Autowired protected MockMvc mvc;
    @Autowired protected JdbcTemplate jdbc;

    @BeforeEach
    void cleanDatabase() {
        jdbc.execute("TRUNCATE trust.issuer RESTART IDENTITY CASCADE");
    }

    protected long insertIssuer(String did, String status) {
        return jdbc.queryForObject(
            "INSERT INTO trust.issuer (did, display_name, status) VALUES (?, ?, ?) RETURNING id",
            Long.class, did, "Test " + did, status);
    }

    protected void insertAuthorization(long issuerId, String credentialType, String status) {
        jdbc.update("INSERT INTO trust.issuer_credential_authorization (issuer_id, credential_type, status) VALUES (?, ?, ?)",
            issuerId, credentialType, status);
    }

    protected ResultActions check(String issuerId, String credentialType) throws Exception {
        return mvc.perform(get("/v1/authorizations/check")
            .param("issuerId", issuerId).param("credentialType", credentialType));
    }

    protected void assertDecision(String issuerId, String credentialType, boolean authorised, String reason) throws Exception {
        check(issuerId, credentialType)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.issuerId").value(issuerId))
            .andExpect(jsonPath("$.credentialType").value(credentialType))
            .andExpect(jsonPath("$.authorised").value(authorised))
            .andExpect(jsonPath("$.reason").value(reason))
            .andExpect(jsonPath("$.apiVersion").value("v1"))
            .andExpect(jsonPath("$.evaluatedAt").isNotEmpty());
    }
}
