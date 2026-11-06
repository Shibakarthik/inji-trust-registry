package io.cdpi.trustregistry;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Iterator;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Verifies the GENERATED specification (no hand-written copy) matches what the code enforces. */
class OpenApiSpecTest extends AbstractPostgresTest {

    private JsonNode spec() throws Exception {
        String json = mvc.perform(get("/v1/openapi.json")).andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return new ObjectMapper().readTree(json);
    }

    @Test
    void versionAndOpenApi3() throws Exception {
        JsonNode spec = spec();
        assertTrue(spec.path("openapi").asText().startsWith("3."), spec.path("openapi").asText());
        assertEquals("v1", spec.path("info").path("version").asText());
        assertEquals("basic", spec.path("components").path("securitySchemes").path("basicAuth").path("scheme").asText());

        JsonNode headerScheme = spec.path("components").path("securitySchemes").path("adminRequestHeader");
        assertEquals("apiKey", headerScheme.path("type").asText());
        assertEquals("header", headerScheme.path("in").asText());
        assertEquals("X-Registry-Admin-Request", headerScheme.path("name").asText());
    }

    @Test
    void publicCheckOperation_hasNoSecurityRequirement_andDocumentsResponses() throws Exception {
        JsonNode spec = spec();
        JsonNode op = spec.path("paths").path("/v1/authorizations/check").path("get");
        assertFalse(op.isMissingNode(), "public check operation missing");
        assertTrue(op.path("security").isMissingNode() || op.path("security").size() == 0,
            "public operation must not require security: " + op.path("security"));
        assertTrue(spec.path("security").isMissingNode() || spec.path("security").size() == 0,
            "no global security requirement expected");
        for (String code : new String[] {"200", "400", "500", "503"}) {
            assertFalse(op.path("responses").path(code).isMissingNode(), "response " + code + " not documented");
        }
        JsonNode reasons = spec.path("components").path("schemas").path("AuthorizationCheckResponse")
            .path("properties").path("reason");
        assertFalse(reasons.isMissingNode());
        String all = spec.toString();
        for (String code : new String[] {"ISSUER_AUTHORIZED", "ISSUER_NOT_FOUND", "ISSUER_INACTIVE",
                "CREDENTIAL_TYPE_NOT_AUTHORIZED", "AUTHORIZATION_REVOKED"}) {
            assertTrue(all.contains(code), "reason code not in spec: " + code);
        }
    }

    @Test
    void everyAdminOperation_requiresBasicAuth_andDocuments401And403() throws Exception {
        JsonNode paths = spec().path("paths");
        int adminOperations = 0;
        Iterator<Map.Entry<String, JsonNode>> it = paths.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> path = it.next();
            if (!path.getKey().startsWith("/v1/admin/")) {
                continue;
            }
            Iterator<Map.Entry<String, JsonNode>> ops = path.getValue().fields();
            while (ops.hasNext()) {
                Map.Entry<String, JsonNode> op = ops.next();
                adminOperations++;
                String where = op.getKey() + " " + path.getKey();
                JsonNode security = op.getValue().path("security").path(0);
                assertFalse(security.path("basicAuth").isMissingNode(),
                    "basicAuth missing for " + where);
                boolean unsafe = switch (op.getKey()) {
                    case "post", "put", "patch", "delete" -> true;
                    default -> false;
                };
                if (unsafe) {
                    assertFalse(security.path("adminRequestHeader").isMissingNode(),
                        "admin request header missing for " + where);
                } else {
                    assertTrue(security.path("adminRequestHeader").isMissingNode(),
                        "read operation must not require admin request header: " + where);
                }
                assertFalse(op.getValue().path("responses").path("401").isMissingNode(), "401 missing for " + where);
                assertFalse(op.getValue().path("responses").path("403").isMissingNode(), "403 missing for " + where);
            }
        }
        assertEquals(9, adminOperations);
    }
}
