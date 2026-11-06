package io.cdpi.trustregistry;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** PostgreSQL (defaults + triggers) is the only timestamp source; the API must report exactly what was persisted. */
class TimestampTest extends AbstractPostgresTest {

    static final String DID = "did:web:example.com:issuer";
    static final RequestPostProcessor ADMIN = httpBasic(ADMIN_USER, ADMIN_PASSWORD);
    final ObjectMapper json = new ObjectMapper();

    private JsonNode body(ResultActions r) throws Exception {
        return json.readTree(r.andReturn().getResponse().getContentAsString());
    }

    private static Instant instant(JsonNode node, String field) {
        return Instant.parse(node.get(field).asText());
    }

    private Instant db(String table, String column) {
        return jdbc.queryForObject("SELECT " + column + " FROM trust." + table, OffsetDateTime.class).toInstant();
    }

    @Test
    void issuerTimestamps_equalThePersistedValues() throws Exception {
        JsonNode created = body(mvc.perform(post("/v1/admin/issuers").with(ADMIN).contentType(MediaType.APPLICATION_JSON)
            .content("{\"did\":\"" + DID + "\",\"displayName\":\"Issuer\"}")).andExpect(status().isCreated()));
        assertEquals(db("issuer", "created_at"), instant(created, "createdAt"));
        assertEquals(db("issuer", "updated_at"), instant(created, "updatedAt"));

        JsonNode deactivated = body(mvc.perform(patch("/v1/admin/issuers/{id}/status", DID).with(ADMIN)
            .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INACTIVE\"}")).andExpect(status().isOk()));
        assertEquals(db("issuer", "updated_at"), instant(deactivated, "updatedAt"));       // trigger value, not app clock
        assertTrue(instant(deactivated, "updatedAt").isAfter(instant(created, "updatedAt")));
        assertEquals(instant(created, "createdAt"), instant(deactivated, "createdAt"));

        JsonNode again = body(mvc.perform(patch("/v1/admin/issuers/{id}/status", DID).with(ADMIN)
            .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INACTIVE\"}")).andExpect(status().isOk()));
        assertEquals(instant(deactivated, "updatedAt"), instant(again, "updatedAt"));     // idempotent: no spurious change
    }

    @Test
    void authorizationTimestamps_equalThePersistedValues() throws Exception {
        insertIssuer(DID, "ACTIVE");
        JsonNode created = body(mvc.perform(post("/v1/admin/issuers/{id}/authorizations", DID).with(ADMIN)
            .contentType(MediaType.APPLICATION_JSON).content("{\"credentialType\":\"FarmerCredential\"}"))
            .andExpect(status().isCreated()));
        String table = "issuer_credential_authorization";
        assertEquals(db(table, "created_at"), instant(created, "createdAt"));
        assertEquals(db(table, "updated_at"), instant(created, "updatedAt"));

        JsonNode revoked = body(mvc.perform(post("/v1/admin/issuers/{id}/authorizations/{t}/revoke", DID, "FarmerCredential")
            .with(ADMIN)).andExpect(status().isOk()));
        assertEquals(db(table, "updated_at"), instant(revoked, "updatedAt"));
        assertTrue(instant(revoked, "updatedAt").isAfter(instant(created, "updatedAt")));

        JsonNode revokedAgain = body(mvc.perform(post("/v1/admin/issuers/{id}/authorizations/{t}/revoke", DID, "FarmerCredential")
            .with(ADMIN)).andExpect(status().isOk()));
        assertEquals(instant(revoked, "updatedAt"), instant(revokedAgain, "updatedAt"));

        JsonNode reactivated = body(mvc.perform(post("/v1/admin/issuers/{id}/authorizations/{t}/reactivate", DID, "FarmerCredential")
            .with(ADMIN)).andExpect(status().isOk()));
        assertEquals(db(table, "updated_at"), instant(reactivated, "updatedAt"));
        assertTrue(instant(reactivated, "updatedAt").isAfter(instant(revoked, "updatedAt")));
    }

    @Test
    void directSqlUpdates_areVisibleThroughTheApi() throws Exception {
        long id = insertIssuer(DID, "ACTIVE");
        jdbc.update("UPDATE trust.issuer SET status = 'INACTIVE' WHERE id = ?", id); // trigger fires
        JsonNode read = body(mvc.perform(get("/v1/admin/issuers/{id}", DID).with(ADMIN)).andExpect(status().isOk()));
        assertEquals(db("issuer", "updated_at"), instant(read, "updatedAt"));
        assertTrue(instant(read, "updatedAt").isAfter(instant(read, "createdAt")));
    }
}
