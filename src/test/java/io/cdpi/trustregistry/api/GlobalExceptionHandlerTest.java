package io.cdpi.trustregistry.api;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.SQLTransientConnectionException;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.postgresql.util.ServerErrorMessage;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.CannotCreateTransactionException;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();
    private final FallbackExceptionHandler fallback = new FallbackExceptionHandler();

    /** A driver exception carrying the structured fields PostgreSQL sends (SQLSTATE and constraint name). */
    private static DataIntegrityViolationException violation(String sqlState, String constraint) {
        ServerErrorMessage message = mock(ServerErrorMessage.class);
        when(message.getSQLState()).thenReturn(sqlState);
        when(message.getConstraint()).thenReturn(constraint);
        return new DataIntegrityViolationException("could not execute statement", new PSQLException(message));
    }

    @Test
    void duplicateIssuerDid_409() {
        assertEquals(409, handler.integrity(violation("23505", "uq_issuer_did")).getStatus());
    }

    @Test
    void duplicateAuthorization_409() {
        assertEquals(409, handler.integrity(violation("23505", "uq_issuer_credential_type")).getStatus());
    }

    @Test
    void messageTextIsNotUsedToDetectConstraints() {
        // looks like a unique violation in prose only: no structured metadata -> must NOT be a 409
        DataIntegrityViolationException textOnly = new DataIntegrityViolationException("x",
            new RuntimeException("ERROR: duplicate key value violates unique constraint \"uq_issuer_did\""));
        assertEquals(500, handler.integrity(textOnly).getStatus());
    }

    @Test
    void otherIntegrityViolations_are500_not409() {
        assertEquals(500, handler.integrity(violation("23505", "some_other_unique")).getStatus());
        assertEquals(500, handler.integrity(violation("23514", "ck_issuer_status")).getStatus());
        assertEquals(500, handler.integrity(violation("23503", "issuer_credential_authorization_issuer_id_fkey")).getStatus());
        // right constraint name but not a unique violation
        assertEquals(500, handler.integrity(violation("23514", "uq_issuer_did")).getStatus());
        assertEquals(500, handler.integrity(new DataIntegrityViolationException("no cause")).getStatus());
    }

    @Test
    void unavailableOrTimedOutDatabase_503_withoutLeakingDetails() {
        ProblemDetail pd = handler.dataStoreFailure(new CannotCreateTransactionException(
            "Could not open JPA EntityManager", new SQLTransientConnectionException("secret-host:5432 refused")));
        assertEquals(503, pd.getStatus());
        assertFalse(String.valueOf(pd.getDetail()).contains("secret-host"));
        assertEquals(503, handler.dataStoreFailure(new QueryTimeoutException("statement timeout")).getStatus());
    }

    @Test
    void otherPersistenceFailures_500() {
        assertEquals(500, handler.dataStoreFailure(new InvalidDataAccessResourceUsageException("bad sql")).getStatus());
    }

    @Test
    void fallbackHandler_500_withoutLeakingDetails() throws Exception {
        ProblemDetail pd = fallback.unexpected(new IllegalStateException("boom: password=hunter2"));
        assertEquals(500, pd.getStatus());
        assertFalse(String.valueOf(pd.getDetail()).contains("hunter2"));
        assertNull(pd.getProperties());
    }

    @Test
    void fallbackHandler_rethrowsSecurityExceptions() {
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
            () -> fallback.unexpected(new org.springframework.security.access.AccessDeniedException("no")));
    }

    @Test
    void handleExceptionInternal_keepsProblemDetailBody_andDoesNotThrowOn5xx() {
        ResponseEntity<Object> response = handler.handleExceptionInternal(new RuntimeException("x"), null,
            new org.springframework.http.HttpHeaders(), HttpStatus.SERVICE_UNAVAILABLE,
            new org.springframework.web.context.request.ServletWebRequest(
                new org.springframework.mock.web.MockHttpServletRequest()));
        assertEquals(503, response.getStatusCode().value());
    }
}
