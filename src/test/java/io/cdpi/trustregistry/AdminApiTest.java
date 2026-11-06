package io.cdpi.trustregistry;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

import io.cdpi.trustregistry.config.SecurityConfig;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

class AdminApiTest extends AbstractPostgresTest {

    static final String DID = "did:web:example.com:issuer";
    static final RequestPostProcessor ADMIN = request -> {
        var authenticated = httpBasic(ADMIN_USER, ADMIN_PASSWORD).postProcessRequest(request);
        authenticated.addHeader(SecurityConfig.ADMIN_REQUEST_HEADER, SecurityConfig.ADMIN_REQUEST_HEADER_VALUE);
        return authenticated;
    };

    private ResultActions register(String did) throws Exception {
        return mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON)
            .content("{\"did\":\"" + did + "\",\"displayName\":\"Test Issuer\"}"));
    }

    private ResultActions authorize(String did, String type) throws Exception {
        return mvc.perform(post("/v1/admin/issuers/{id}/authorizations", did).with(ADMIN)
            .contentType(MediaType.APPLICATION_JSON).content("{\"credentialType\":\"" + type + "\"}"));
    }

    private ResultActions revoke(String did, String type) throws Exception {
        return mvc.perform(post("/v1/admin/issuers/{id}/authorizations/{t}/revoke", did, type).with(ADMIN));
    }

    private ResultActions reactivate(String did, String type) throws Exception {
        return mvc.perform(post("/v1/admin/issuers/{id}/authorizations/{t}/reactivate", did, type).with(ADMIN));
    }

    private ResultActions setIssuerStatus(String did, String status) throws Exception {
        return mvc.perform(patch("/v1/admin/issuers/{id}/status", did).with(ADMIN)
            .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"" + status + "\"}"));
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM trust." + table, Integer.class);
    }

    // ---- issuers ----

    @Test
    void registerIssuer_createsActiveIssuerWithoutAuthorizations() throws Exception {
        register("did:web:Shibakarthik.github.io:collab:farmer")
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.did").value("did:web:Shibakarthik.github.io:collab:farmer"))
            .andExpect(jsonPath("$.status").value("ACTIVE"));
        assertEquals(1, count("issuer"));
        assertEquals(0, count("issuer_credential_authorization"));
        assertDecision("did:web:Shibakarthik.github.io:collab:farmer", "FarmerCredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }

    @Test
    void duplicateIssuer_409() throws Exception {
        register(DID).andExpect(status().isCreated());
        register(DID).andExpect(status().isConflict())
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
        assertEquals(1, count("issuer"));
    }

    @Test
    void issuerDidsDifferingOnlyByCaseAreDistinctIssuers() throws Exception {
        register("did:web:Example.com:issuer").andExpect(status().isCreated());
        register("did:web:example.com:issuer").andExpect(status().isCreated());
        assertEquals(2, count("issuer"));
    }

    @Test
    void getAndListIssuers() throws Exception {
        register(DID).andExpect(status().isCreated());
        mvc.perform(get("/v1/admin/issuers/{id}", DID).with(ADMIN))
            .andExpect(status().isOk()).andExpect(jsonPath("$.did").value(DID));
        mvc.perform(get("/v1/admin/issuers").with(ADMIN))
            .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/v1/admin/issuers/{id}", "did:web:nobody.example").with(ADMIN))
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
    }

    @Test
    void deactivateAndReactivateIssuer() throws Exception {
        register(DID).andExpect(status().isCreated());
        authorize(DID, "FarmerCredential").andExpect(status().isCreated());

        setIssuerStatus(DID, "INACTIVE").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("INACTIVE"));
        assertDecision(DID, "FarmerCredential", false, "ISSUER_INACTIVE");
        setIssuerStatus(DID, "INACTIVE").andExpect(status().isOk()); // idempotent

        setIssuerStatus(DID, "ACTIVE").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ACTIVE"));
        assertDecision(DID, "FarmerCredential", true, "ISSUER_AUTHORIZED");
    }

    @Test
    void invalidIssuerRequests_400() throws Exception {
        register("not-a-did").andExpect(status().isBadRequest());
        mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON)
            .content("{\"did\":\"" + DID + "\",\"displayName\":\"   \"}")).andExpect(status().isBadRequest());
        mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON)
            .content("{\"did\":\"" + DID + "\",\"displayName\":\"" + "x".repeat(256) + "\"}")).andExpect(status().isBadRequest());
        mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON)
            .content("not json")).andExpect(status().isBadRequest());
        register(DID).andExpect(status().isCreated());
        setIssuerStatus(DID, "BANANA").andExpect(status().isBadRequest());
        assertEquals(1, count("issuer"));
    }

    // ---- authorisations ----

    @Test
    void authorize_201_thenDuplicate409_evenWhenRevoked() throws Exception {
        register(DID).andExpect(status().isCreated());
        authorize(DID, "FarmerCredential").andExpect(status().isCreated())
            .andExpect(jsonPath("$.issuerId").value(DID))
            .andExpect(jsonPath("$.credentialType").value("FarmerCredential"))
            .andExpect(jsonPath("$.status").value("ACTIVE"));
        authorize(DID, "FarmerCredential").andExpect(status().isConflict());

        revoke(DID, "FarmerCredential").andExpect(status().isOk());
        authorize(DID, "FarmerCredential").andExpect(status().isConflict()); // never silently reactivates
        assertDecision(DID, "FarmerCredential", false, "AUTHORIZATION_REVOKED");
        assertEquals(1, count("issuer_credential_authorization"));
    }

    @Test
    void authorizeUnknownIssuer_404_andInvalidType_400() throws Exception {
        authorize("did:web:nobody.example", "FarmerCredential").andExpect(status().isNotFound());
        register(DID).andExpect(status().isCreated());
        authorize(DID, "Farmer Credential").andExpect(status().isBadRequest());
        assertEquals(0, count("issuer_credential_authorization"));
    }

    @Test
    void revokeAndReactivate_areIdempotent_andRecordsAreRetained() throws Exception {
        register(DID).andExpect(status().isCreated());
        authorize(DID, "FarmerCredential").andExpect(status().isCreated());

        revoke(DID, "FarmerCredential").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("REVOKED"));
        revoke(DID, "FarmerCredential").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("REVOKED"));
        assertDecision(DID, "FarmerCredential", false, "AUTHORIZATION_REVOKED");
        // the revoked record still exists
        assertEquals(1, count("issuer_credential_authorization"));
        assertEquals("REVOKED", jdbc.queryForObject(
            "SELECT status FROM trust.issuer_credential_authorization", String.class));
        mvc.perform(get("/v1/admin/issuers/{id}/authorizations", DID).with(ADMIN))
            .andExpect(status().isOk()).andExpect(jsonPath("$[0].status").value("REVOKED"));

        reactivate(DID, "FarmerCredential").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ACTIVE"));
        reactivate(DID, "FarmerCredential").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("ACTIVE"));
        assertDecision(DID, "FarmerCredential", true, "ISSUER_AUTHORIZED");
        assertEquals(1, count("issuer_credential_authorization"));
    }

    @Test
    void revokeOrReactivateMissingAuthorization_404() throws Exception {
        register(DID).andExpect(status().isCreated());
        revoke(DID, "FarmerCredential").andExpect(status().isNotFound());
        reactivate(DID, "FarmerCredential").andExpect(status().isNotFound());
        revoke("did:web:nobody.example", "FarmerCredential").andExpect(status().isNotFound());
    }

    @Test
    void listAuthorizations_filters() throws Exception {
        register(DID).andExpect(status().isCreated());
        authorize(DID, "FarmerCredential").andExpect(status().isCreated());
        authorize(DID, "DrivingLicenceCredential").andExpect(status().isCreated());
        revoke(DID, "DrivingLicenceCredential").andExpect(status().isOk());

        mvc.perform(get("/v1/admin/authorizations").with(ADMIN)).andExpect(jsonPath("$.length()").value(2));
        mvc.perform(get("/v1/admin/authorizations").param("status", "REVOKED").with(ADMIN))
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].credentialType").value("DrivingLicenceCredential"));
        mvc.perform(get("/v1/admin/authorizations").param("credentialType", "FarmerCredential").with(ADMIN))
            .andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/v1/admin/authorizations").param("issuerId", DID).with(ADMIN))
            .andExpect(jsonPath("$.length()").value(2));
    }

    // ---- pagination ----

    @Test
    void invalidPagination_400() throws Exception {
        for (String path : List.of("/v1/admin/issuers", "/v1/admin/authorizations")) {
            mvc.perform(get(path).param("page", "-1").with(ADMIN)).andExpect(status().isBadRequest());
            mvc.perform(get(path).param("size", "0").with(ADMIN)).andExpect(status().isBadRequest());
            mvc.perform(get(path).param("size", "201").with(ADMIN)).andExpect(status().isBadRequest());
            mvc.perform(get(path).param("size", "abc").with(ADMIN)).andExpect(status().isBadRequest());
            mvc.perform(get(path).param("page", "0").param("size", "200").with(ADMIN)).andExpect(status().isOk());
        }
    }

    // ---- concurrency: the unique constraints are the final protection ----

    private List<Integer> concurrently(int n, Callable<Integer> task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try {
            CountDownLatch ready = new CountDownLatch(n);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return task.call();
                }));
            }
            ready.await();
            go.countDown();
            List<Integer> statuses = new ArrayList<>();
            for (Future<Integer> f : futures) {
                statuses.add(f.get(60, TimeUnit.SECONDS));
            }
            return statuses;
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentDuplicateIssuerRegistration_exactlyOne201_restAre409() throws Exception {
        int n = 8;
        List<Integer> statuses = concurrently(n, () -> register(DID).andReturn().getResponse().getStatus());
        assertEquals(1, Collections.frequency(statuses, 201), statuses.toString());
        assertEquals(n - 1, Collections.frequency(statuses, 409), statuses.toString());
        assertEquals(1, count("issuer"));
    }

    @Test
    void concurrentDuplicateAuthorization_exactlyOne201_restAre409() throws Exception {
        register(DID).andExpect(status().isCreated());
        int n = 8;
        List<Integer> statuses = concurrently(n, () -> authorize(DID, "FarmerCredential").andReturn().getResponse().getStatus());
        assertEquals(1, Collections.frequency(statuses, 201), statuses.toString());
        assertEquals(n - 1, Collections.frequency(statuses, 409), statuses.toString());
        assertEquals(1, count("issuer_credential_authorization"));
    }

    // ---- the assessment flow ----

    @Test
    void fullLifecycle() throws Exception {
        register(DID).andExpect(status().isCreated());
        assertDecision(DID, "FarmerCredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
        authorize(DID, "FarmerCredential").andExpect(status().isCreated());
        assertDecision(DID, "FarmerCredential", true, "ISSUER_AUTHORIZED");
        revoke(DID, "FarmerCredential").andExpect(status().isOk());
        assertDecision(DID, "FarmerCredential", false, "AUTHORIZATION_REVOKED");
        reactivate(DID, "FarmerCredential").andExpect(status().isOk());
        assertDecision(DID, "FarmerCredential", true, "ISSUER_AUTHORIZED");
        setIssuerStatus(DID, "INACTIVE").andExpect(status().isOk());
        assertDecision(DID, "FarmerCredential", false, "ISSUER_INACTIVE");
    }
}
