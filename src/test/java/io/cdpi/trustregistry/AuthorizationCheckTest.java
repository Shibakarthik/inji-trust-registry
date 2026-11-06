package io.cdpi.trustregistry;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.ResultActions;

/** Public read endpoint; no credentials are supplied anywhere in this class. */
class AuthorizationCheckTest extends AbstractPostgresTest {

    static final String ISSUER = "did:web:example.com:issuer";

    private static ResultActions noStore(ResultActions r) throws Exception {
        return r.andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void unknownIssuer_ISSUER_NOT_FOUND() throws Exception {
        assertDecision("did:web:unknown.example", "FarmerCredential", false, "ISSUER_NOT_FOUND");
    }

    @Test
    void inactiveIssuer_ISSUER_INACTIVE_evenWithActiveAuthorization() throws Exception {
        long id = insertIssuer(ISSUER, "INACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");
        assertDecision(ISSUER, "FarmerCredential", false, "ISSUER_INACTIVE");
    }

    @Test
    void activeIssuerWithoutMapping_CREDENTIAL_TYPE_NOT_AUTHORIZED() throws Exception {
        long id = insertIssuer(ISSUER, "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");
        assertDecision(ISSUER, "DrivingLicenceCredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }

    @Test
    void registrationAloneAuthorisesNothing() throws Exception {
        insertIssuer(ISSUER, "ACTIVE");
        assertDecision(ISSUER, "FarmerCredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }

    @Test
    void authorisationIsPerIssuer() throws Exception {
        long a = insertIssuer(ISSUER, "ACTIVE");
        insertIssuer("did:web:other.example", "ACTIVE");
        insertAuthorization(a, "FarmerCredential", "ACTIVE");
        assertDecision("did:web:other.example", "FarmerCredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }

    @Test
    void activeIssuerWithRevokedMapping_AUTHORIZATION_REVOKED() throws Exception {
        long id = insertIssuer(ISSUER, "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "REVOKED");
        assertDecision(ISSUER, "FarmerCredential", false, "AUTHORIZATION_REVOKED");
    }

    @Test
    void activeIssuerWithActiveMapping_ISSUER_AUTHORIZED() throws Exception {
        long id = insertIssuer(ISSUER, "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");
        assertDecision(ISSUER, "FarmerCredential", true, "ISSUER_AUTHORIZED");
    }

    @Test
    void projectSampleDid_isAccepted() throws Exception {
        String did = "did:web:Shibakarthik.github.io:collab:farmer";
        long id = insertIssuer(did, "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");
        assertDecision(did, "FarmerCredential", true, "ISSUER_AUTHORIZED");
        assertDecision(did, "DrivingLicenceCredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }

    @Test
    void issuerMatchingIsExactAndCaseSensitive() throws Exception {
        long id = insertIssuer("did:web:Example.com:Issuer", "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");

        assertDecision("did:web:Example.com:Issuer", "FarmerCredential", true, "ISSUER_AUTHORIZED");
        assertDecision("did:web:example.com:issuer", "FarmerCredential", false, "ISSUER_NOT_FOUND");
        assertDecision("did:web:EXAMPLE.COM:ISSUER", "FarmerCredential", false, "ISSUER_NOT_FOUND");
    }

    @Test
    void credentialTypeMatchingIsExactAndCaseSensitive() throws Exception {
        long id = insertIssuer(ISSUER, "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "ACTIVE");

        assertDecision(ISSUER, "FarmerCredential", true, "ISSUER_AUTHORIZED");
        assertDecision(ISSUER, "farmercredential", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
        assertDecision(ISSUER, "FARMERCREDENTIAL", false, "CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }

    @Test
    void missingParameters_400() throws Exception {
        noStore(mvc.perform(get("/v1/authorizations/check").param("credentialType", "FarmerCredential")))
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
            .andExpect(jsonPath("$.authorised").doesNotExist());
        noStore(mvc.perform(get("/v1/authorizations/check").param("issuerId", ISSUER)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.authorised").doesNotExist());
        noStore(mvc.perform(get("/v1/authorizations/check"))).andExpect(status().isBadRequest());
    }

    @Test
    void blankParameters_400() throws Exception {
        noStore(check("", "FarmerCredential")).andExpect(status().isBadRequest());
        noStore(check("   ", "FarmerCredential")).andExpect(status().isBadRequest());
        noStore(check(ISSUER, "")).andExpect(status().isBadRequest());
        noStore(check(ISSUER, "   ")).andExpect(status().isBadRequest());
    }

    @Test
    void malformedParameters_400() throws Exception {
        noStore(check("not-a-did", "FarmerCredential")).andExpect(status().isBadRequest());
        noStore(check("did:web:exa mple.com", "FarmerCredential")).andExpect(status().isBadRequest());
        noStore(check("did:web:", "FarmerCredential")).andExpect(status().isBadRequest());
        noStore(check("did:web:" + "a".repeat(600), "FarmerCredential")).andExpect(status().isBadRequest());
        noStore(check(ISSUER, "Farmer Credential")).andExpect(status().isBadRequest());
        noStore(check(ISSUER, "a".repeat(129))).andExpect(status().isBadRequest());
        noStore(check(ISSUER, "x'; DROP TABLE trust.issuer;--")).andExpect(status().isBadRequest());
    }

    @Test
    void successfulDecisions_areNotCacheable() throws Exception {
        noStore(check(ISSUER, "FarmerCredential")).andExpect(status().isOk());
    }

    @Test
    void publicEndpointNeedsNoCredentials_andOnlyGetIsPublic() throws Exception {
        check(ISSUER, "FarmerCredential").andExpect(status().isOk())
            .andExpect(header().doesNotExist("WWW-Authenticate"));
        noStore(mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
            .post("/v1/authorizations/check"))).andExpect(status().isUnauthorized());
    }

    @Test
    void worksUnderAConfiguredContextPath_withNoStore() throws Exception {
        noStore(mvc.perform(get("/registry/v1/authorizations/check").contextPath("/registry")
                .param("issuerId", ISSUER).param("credentialType", "FarmerCredential")))
            .andExpect(status().isOk());
        noStore(mvc.perform(get("/registry/v1/authorizations/check").contextPath("/registry")
                .param("issuerId", "not-a-did").param("credentialType", "FarmerCredential")))
            .andExpect(status().isBadRequest());
    }
}
