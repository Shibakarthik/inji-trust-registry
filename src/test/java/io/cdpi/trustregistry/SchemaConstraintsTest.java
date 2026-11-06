package io.cdpi.trustregistry;

import static org.junit.jupiter.api.Assertions.*;

import java.time.OffsetDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/** Verifies db/init/01-schema.sql itself: constraints, indexes, FK behaviour and updated_at triggers. */
class SchemaConstraintsTest extends AbstractPostgresTest {

    private OffsetDateTime ts(String table, String column, long id) {
        return jdbc.queryForObject("SELECT " + column + " FROM trust." + table + " WHERE id = ?", OffsetDateTime.class, id);
    }

    private long authorizationId() {
        return jdbc.queryForObject("SELECT id FROM trust.issuer_credential_authorization", Long.class);
    }

    @Test
    void uniqueDidAndUniqueIssuerCredentialType() {
        long id = insertIssuer("did:web:a.example", "ACTIVE");
        assertThrows(DataIntegrityViolationException.class, () -> insertIssuer("did:web:a.example", "ACTIVE"));
        insertAuthorization(id, "FarmerCredential", "ACTIVE");
        assertThrows(DataIntegrityViolationException.class, () -> insertAuthorization(id, "FarmerCredential", "REVOKED"));
    }

    @Test
    void statusValuesAreRestricted() {
        assertThrows(DataIntegrityViolationException.class, () -> insertIssuer("did:web:a.example", "BANANA"));
        long id = insertIssuer("did:web:b.example", "ACTIVE");
        assertThrows(DataIntegrityViolationException.class, () -> insertAuthorization(id, "FarmerCredential", "INACTIVE"));
        assertThrows(DataIntegrityViolationException.class, () -> insertAuthorization(id, "FarmerCredential", "BANANA"));
    }

    @Test
    void foreignKeyExistsAndIssuerDeletionIsNotCascaded() {
        assertThrows(DataIntegrityViolationException.class, () -> insertAuthorization(999_999L, "FarmerCredential", "ACTIVE"));
        long id = insertIssuer("did:web:a.example", "ACTIVE");
        insertAuthorization(id, "FarmerCredential", "REVOKED");

        assertThrows(DataIntegrityViolationException.class,
            () -> jdbc.update("DELETE FROM trust.issuer WHERE id = ?", id));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM trust.issuer", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM trust.issuer_credential_authorization", Integer.class));
    }

    @Test
    void requiredIndexesExist() {
        List<String> indexes = jdbc.queryForList(
            "SELECT indexname FROM pg_indexes WHERE schemaname = 'trust'", String.class);
        assertTrue(indexes.contains("uq_issuer_did"), indexes.toString());
        assertTrue(indexes.contains("uq_issuer_credential_type"), indexes.toString());
        assertTrue(indexes.contains("idx_authorization_credential_type"), indexes.toString());
    }

    @Test
    void updatedAtTriggerWorksOnIssuer() {
        long id = insertIssuer("did:web:a.example", "ACTIVE");
        OffsetDateTime created = ts("issuer", "created_at", id);
        OffsetDateTime before = ts("issuer", "updated_at", id);

        jdbc.update("UPDATE trust.issuer SET status = 'INACTIVE' WHERE id = ?", id);

        assertTrue(ts("issuer", "updated_at", id).isAfter(before));
        assertEquals(created, ts("issuer", "created_at", id));
    }

    @Test
    void updatedAtTriggerWorksOnAuthorization() {
        long issuerId = insertIssuer("did:web:a.example", "ACTIVE");
        insertAuthorization(issuerId, "FarmerCredential", "ACTIVE");
        long id = authorizationId();
        OffsetDateTime created = ts("issuer_credential_authorization", "created_at", id);
        OffsetDateTime before = ts("issuer_credential_authorization", "updated_at", id);

        jdbc.update("UPDATE trust.issuer_credential_authorization SET status = 'REVOKED' WHERE id = ?", id);

        assertTrue(ts("issuer_credential_authorization", "updated_at", id).isAfter(before));
        assertEquals(created, ts("issuer_credential_authorization", "created_at", id));
    }
}
