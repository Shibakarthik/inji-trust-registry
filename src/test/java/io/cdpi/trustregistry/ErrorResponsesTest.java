package io.cdpi.trustregistry;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

import io.cdpi.trustregistry.config.SecurityConfig;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** RFC 9457 responses through the real handler chain, plus admin list-filter validation. */
class ErrorResponsesTest extends AbstractPostgresTest {

    static final RequestPostProcessor ADMIN = request -> {
        var authenticated = httpBasic(ADMIN_USER, ADMIN_PASSWORD).postProcessRequest(request);
        authenticated.addHeader(SecurityConfig.ADMIN_REQUEST_HEADER, SecurityConfig.ADMIN_REQUEST_HEADER_VALUE);
        return authenticated;
    };
    static final String PROBLEM = "application/problem+json";

    @Test
    void unexpectedException_500_problemJson_noLeak() throws Exception {
        mvc.perform(get("/v1/admin/test-failure/runtime").with(ADMIN))
            .andExpect(status().isInternalServerError())
            .andExpect(content().contentTypeCompatibleWith(PROBLEM))
            .andExpect(jsonPath("$.status").value(500))
            .andExpect(jsonPath("$.authorised").doesNotExist())
            .andExpect(content().string(not(containsString("hunter2"))))
            .andExpect(content().string(not(containsString("secret-internal-detail"))));
    }

    @Test
    void unrelatedIntegrityViolation_500_not409() throws Exception {
        mvc.perform(get("/v1/admin/test-failure/integrity-other").with(ADMIN))
            .andExpect(status().isInternalServerError())
            .andExpect(content().contentTypeCompatibleWith(PROBLEM))
            .andExpect(content().string(not(containsString("secret-table-detail"))));
    }

    @Test
    void queryTimeout_503_problemJson_noLeak() throws Exception {
        mvc.perform(get("/v1/admin/test-failure/unavailable").with(ADMIN))
            .andExpect(status().isServiceUnavailable())
            .andExpect(content().contentTypeCompatibleWith(PROBLEM))
            .andExpect(content().string(not(containsString("secret-host"))));
    }

    @Test
    void standardMvcErrors_areProblemJson() throws Exception {
        mvc.perform(get("/v1/admin/does-not-exist").with(ADMIN))
            .andExpect(status().isNotFound()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
        mvc.perform(put("/v1/admin/issuers").with(ADMIN))
            .andExpect(status().isMethodNotAllowed()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
        mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.TEXT_PLAIN).content("x"))
            .andExpect(status().isUnsupportedMediaType()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
        mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON).content("{broken"))
            .andExpect(status().isBadRequest()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
        mvc.perform(get("/v1/admin/issuers").param("page", "abc").with(ADMIN))
            .andExpect(status().isBadRequest()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
    }

    @Test
    void malformedOptionalAuthorizationFilters_400() throws Exception {
        for (String bad : List.of("not-a-did", "", "   ", "did:web:a b", "did:web:" + "a".repeat(600))) {
            mvc.perform(get("/v1/admin/authorizations").param("issuerId", bad).with(ADMIN))
                .andExpect(status().isBadRequest()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
        }
        for (String bad : List.of("", "   ", "a b", "x/y", "-x", "a".repeat(129))) {
            mvc.perform(get("/v1/admin/authorizations").param("credentialType", bad).with(ADMIN))
                .andExpect(status().isBadRequest()).andExpect(content().contentTypeCompatibleWith(PROBLEM));
        }
    }

    @Test
    void authorizationFiltersAreExactAndCaseSensitive() throws Exception {
        long id = insertIssuer("did:web:Example.com:Issuer", "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");

        mvc.perform(get("/v1/admin/authorizations").param("issuerId", "did:web:Example.com:Issuer").with(ADMIN))
            .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/v1/admin/authorizations").param("issuerId", "did:web:example.com:issuer").with(ADMIN))
            .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/v1/admin/authorizations").param("credentialType", "FarmerCredential").with(ADMIN))
            .andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/v1/admin/authorizations").param("credentialType", "farmercredential").with(ADMIN))
            .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void displayNameValidationIsEnforcedConsistently() throws Exception {
        String did = "\"did\":\"did:web:example.com:issuer\"";
        mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON)
            .content("{" + did + ",\"displayName\":\"" + "x".repeat(255) + "\"}")).andExpect(status().isCreated());
        for (String body : List.of(
                "{\"did\":\"did:web:two.example\",\"displayName\":\"\"}",
                "{\"did\":\"did:web:two.example\",\"displayName\":\"   \"}",
                "{\"did\":\"did:web:two.example\"}",
                "{\"did\":\"did:web:two.example\",\"displayName\":\"" + "x".repeat(256) + "\"}")) {
            mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        }
    }
}
