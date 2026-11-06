package io.cdpi.trustregistry.error;

import static org.junit.jupiter.api.Assertions.*;

import io.cdpi.trustregistry.AbstractPostgresTest;
import io.cdpi.trustregistry.domain.Issuer;
import io.cdpi.trustregistry.domain.IssuerCredentialAuthorization;
import io.cdpi.trustregistry.repository.AuthorizationRepository;
import io.cdpi.trustregistry.repository.IssuerRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;

/** Exercises the real PostgreSQL/Hibernate exception chains produced by the actual schema. */
class ConstraintViolationsTest extends AbstractPostgresTest {

    @Autowired IssuerRepository issuers;
    @Autowired AuthorizationRepository authorizations;

    @Test
    void duplicateIssuerThroughJpa_identifiesUqIssuerDid() {
        issuers.saveAndFlush(new Issuer("did:web:a.example", "A"));
        DataIntegrityViolationException e = assertThrows(DataIntegrityViolationException.class,
            () -> issuers.saveAndFlush(new Issuer("did:web:a.example", "A again")));
        assertEquals(Optional.of(ConstraintViolations.UQ_ISSUER_DID), ConstraintViolations.uniqueConstraintName(e));
    }

    @Test
    void duplicateAuthorizationThroughJpa_identifiesUqIssuerCredentialType() {
        Issuer issuer = issuers.saveAndFlush(new Issuer("did:web:a.example", "A"));
        authorizations.saveAndFlush(new IssuerCredentialAuthorization(issuer, "FarmerCredential"));
        DataIntegrityViolationException e = assertThrows(DataIntegrityViolationException.class,
            () -> authorizations.saveAndFlush(new IssuerCredentialAuthorization(issuer, "FarmerCredential")));
        assertEquals(Optional.of(ConstraintViolations.UQ_ISSUER_CREDENTIAL_TYPE), ConstraintViolations.uniqueConstraintName(e));
    }

    @Test
    void duplicateThroughPlainJdbc_isIdentifiedToo() {
        insertIssuer("did:web:a.example", "ACTIVE");
        DataIntegrityViolationException e = assertThrows(DataIntegrityViolationException.class,
            () -> insertIssuer("did:web:a.example", "ACTIVE"));
        assertEquals(Optional.of("uq_issuer_did"), ConstraintViolations.uniqueConstraintName(e));
    }

    @Test
    void nonUniqueViolations_areNotReportedAsUnique() {
        DataIntegrityViolationException check = assertThrows(DataIntegrityViolationException.class,
            () -> insertIssuer("did:web:b.example", "BANANA"));
        assertEquals(Optional.empty(), ConstraintViolations.uniqueConstraintName(check));

        DataIntegrityViolationException fk = assertThrows(DataIntegrityViolationException.class,
            () -> insertAuthorization(999_999L, "FarmerCredential", "ACTIVE"));
        assertEquals(Optional.empty(), ConstraintViolations.uniqueConstraintName(fk));

        DataIntegrityViolationException notNull = assertThrows(DataIntegrityViolationException.class,
            () -> jdbc.update("INSERT INTO trust.issuer (did, display_name) VALUES (?, NULL)", "did:web:c.example"));
        assertEquals(Optional.empty(), ConstraintViolations.uniqueConstraintName(notNull));
    }
}
