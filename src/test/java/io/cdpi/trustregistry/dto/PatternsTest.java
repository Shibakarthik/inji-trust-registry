package io.cdpi.trustregistry.dto;

import static org.junit.jupiter.api.Assertions.*;

import io.cdpi.trustregistry.error.Errors;
import org.junit.jupiter.api.Test;

class PatternsTest {

    @Test
    void acceptsLegitimateDids_preservingCase() {
        for (String did : new String[] {
                "did:web:Shibakarthik.github.io:collab:farmer",
                "did:web:example.com:issuer",
                "did:web:example.com%3A8443:path:to:issuer",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "did:example:123456789abcdefghi"}) {
            assertEquals(did, Patterns.requireIssuerId(did));
        }
    }

    @Test
    void rejectsMalformedDids() {
        for (String did : new String[] {
                null, "", " ", "did:web:", "did:web", "DID:web:x", "did:Web:x", "did:web:x:", "did:web:a b",
                "did:web:a/b", "did:web:a?x=1", "did:web:a#frag", "did:web:a%zz", "did:web:x\n", "http://example.com",
                "did:web:" + "a".repeat(600)}) {
            assertThrows(Errors.InvalidRequest.class, () -> Patterns.requireIssuerId(did), String.valueOf(did));
        }
    }

    @Test
    void acceptsAndRejectsCredentialTypes() {
        for (String t : new String[] {"FarmerCredential", "farmercredential", "vc.Farmer-Credential_v2", "urn:farmer:1", "A"}) {
            assertEquals(t, Patterns.requireCredentialType(t));
        }
        assertEquals(128, Patterns.requireCredentialType("a".repeat(128)).length());
        for (String t : new String[] {null, "", " ", "a b", "a/b", "../x", "-x", "a'b", "x; drop", "a\n", "a".repeat(129)}) {
            assertThrows(Errors.InvalidRequest.class, () -> Patterns.requireCredentialType(t), String.valueOf(t));
        }
    }

    @Test
    void displayNameLimits() {
        assertEquals("Issuer", Patterns.requireDisplayName("Issuer"));
        assertThrows(Errors.InvalidRequest.class, () -> Patterns.requireDisplayName("  "));
        assertThrows(Errors.InvalidRequest.class, () -> Patterns.requireDisplayName("x".repeat(256)));
    }
}
