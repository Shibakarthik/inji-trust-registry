package io.cdpi.trustregistry;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import io.cdpi.trustregistry.config.SecurityConfig;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

class SecurityTest extends AbstractPostgresTest {

    static final String DID = "did:web:example.com:issuer";
    static final RequestPostProcessor ADMIN = request -> {
        var authenticated = httpBasic(ADMIN_USER, ADMIN_PASSWORD).postProcessRequest(request);
        authenticated.addHeader(SecurityConfig.ADMIN_REQUEST_HEADER, SecurityConfig.ADMIN_REQUEST_HEADER_VALUE);
        return authenticated;
    };

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM trust." + table, Integer.class);
    }

    @Test
    void publicEndpoints_workWithoutCredentials() throws Exception {
        check(DID, "FarmerCredential").andExpect(status().isOk());
        mvc.perform(get("/v1/openapi.json")).andExpect(status().isOk());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
        mvc.perform(get("/swagger-ui.html")).andExpect(result -> assertTrue(result.getResponse().getStatus() < 400));
        mvc.perform(get("/swagger-ui/index.html")).andExpect(result -> assertTrue(result.getResponse().getStatus() < 400));
    }

    @Test
    void adminReadEndpoints_401WithoutCredentials_asProblemJson() throws Exception {
        mvc.perform(get("/v1/admin/issuers"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("WWW-Authenticate"))
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.status").value(401));
        mvc.perform(get("/v1/admin/authorizations")).andExpect(status().isUnauthorized());
        mvc.perform(get("/v1/admin/issuers/{id}", DID)).andExpect(status().isUnauthorized());
    }

    @Test
    void invalidCredentials_401() throws Exception {
        mvc.perform(get("/v1/admin/issuers").with(httpBasic(ADMIN_USER, "wrong-password-xyz")))
            .andExpect(status().isUnauthorized());
        mvc.perform(get("/v1/admin/issuers").with(httpBasic("someone-else", ADMIN_PASSWORD)))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void validCredentials_work() throws Exception {
        mvc.perform(get("/v1/admin/issuers").with(httpBasic(ADMIN_USER, ADMIN_PASSWORD))).andExpect(status().isOk());
    }

    @Test
    void adminWritesRequireTheCustomHeader_evenWithValidBasicCredentials() throws Exception {
        for (Supplier<MockHttpServletRequestBuilder> op : adminWriteOperations()) {
            mvc.perform(op.get().with(httpBasic(ADMIN_USER, ADMIN_PASSWORD)))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
            mvc.perform(op.get().with(ADMIN)).andExpect(result -> {
                int s = result.getResponse().getStatus();
                assertTrue(s != 401 && s != 403, "admin with required header must pass security, got " + s);
            });
        }
    }

    @Test
    void unauthenticatedUsersCannotPerformAnyAdminWrite() throws Exception {
        for (Supplier<MockHttpServletRequestBuilder> op : adminWriteOperations()) {
            mvc.perform(op.get()).andExpect(result -> {
                int status = result.getResponse().getStatus();
                assertTrue(status == 401 || status == 403, "anonymous write must be denied, got " + status);
            });
        }
        assertEquals(0, count("issuer"));
        assertEquals(0, count("issuer_credential_authorization"));
    }

    @Test
    void authenticatedButNotAdmin_403_asProblemJson() throws Exception {
        mvc.perform(get("/v1/admin/issuers").with(user("bob").roles("VIEWER")))
            .andExpect(status().isForbidden())
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void unlistedEndpointsAreDeniedByDefault() throws Exception {
        for (String path : List.of("/", "/actuator", "/actuator/env", "/actuator/beans", "/error", "/h2-console", "/v1")) {
            mvc.perform(get(path)).andExpect(status().isUnauthorized());
            mvc.perform(get(path).with(httpBasic(ADMIN_USER, ADMIN_PASSWORD))).andExpect(status().isForbidden());
        }
    }

    @Test
    void corsIsOnlyEnabledForThePublicCheckEndpoint() throws Exception {
        mvc.perform(options("/v1/authorizations/check")
                .header("Origin", "https://verifier.example").header("Access-Control-Request-Method", "GET"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "*"));
        mvc.perform(get("/v1/authorizations/check").param("issuerId", DID).param("credentialType", "FarmerCredential")
                .header("Origin", "https://verifier.example"))
            .andExpect(header().string("Access-Control-Allow-Origin", "*"))
            .andExpect(header().doesNotExist("Access-Control-Allow-Credentials"));

        mvc.perform(options("/v1/admin/issuers")
                .header("Origin", "https://evil.example").header("Access-Control-Request-Method", "POST"))
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
        mvc.perform(get("/v1/admin/issuers").with(httpBasic(ADMIN_USER, ADMIN_PASSWORD)).header("Origin", "https://evil.example"))
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    private static List<Supplier<MockHttpServletRequestBuilder>> adminWriteOperations() {
        String json = MediaType.APPLICATION_JSON_VALUE;
        String d = "did:web:x.example";
        return List.of(
            () -> post("/v1/admin/issuers").contentType(json).content("{\"did\":\"" + d + "\",\"displayName\":\"x\"}"),
            () -> patch("/v1/admin/issuers/" + d + "/status").contentType(json).content("{\"status\":\"INACTIVE\"}"),
            () -> post("/v1/admin/issuers/" + d + "/authorizations").contentType(json).content("{\"credentialType\":\"FarmerCredential\"}"),
            () -> post("/v1/admin/issuers/" + d + "/authorizations/FarmerCredential/revoke"),
            () -> post("/v1/admin/issuers/" + d + "/authorizations/FarmerCredential/reactivate"));
    }

    private static List<Supplier<MockHttpServletRequestBuilder>> adminOperations() {
        String d = "did:web:x.example";
        return List.of(
            () -> get("/v1/admin/issuers"),
            () -> get("/v1/admin/issuers/" + d),
            () -> get("/v1/admin/issuers/" + d + "/authorizations"),
            () -> get("/v1/admin/authorizations"));
    }

    @Test
    void everyAdminOperation_requiresTheAdministratorRole() throws Exception {
        insertIssuer("did:web:x.example", "ACTIVE");
        for (Supplier<MockHttpServletRequestBuilder> op : adminOperations()) {
            mvc.perform(op.get()).andExpect(status().isUnauthorized());
            mvc.perform(op.get().with(httpBasic(ADMIN_USER, "wrong-password-xyz"))).andExpect(status().isUnauthorized());
            mvc.perform(op.get().with(user("bob").roles("VIEWER"))).andExpect(status().isForbidden());
            mvc.perform(op.get().with(httpBasic(ADMIN_USER, ADMIN_PASSWORD))).andExpect(status().isOk());
        }
        // The issuer is deliberately seeded above so the detail/list operations can return 200.
        assertEquals(1, count("issuer"));
    }
}
