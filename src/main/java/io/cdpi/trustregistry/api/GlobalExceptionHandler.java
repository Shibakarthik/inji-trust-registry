package io.cdpi.trustregistry.api;

import io.cdpi.trustregistry.error.ConstraintViolations;
import io.cdpi.trustregistry.error.Errors;
import java.sql.SQLRecoverableException;
import java.sql.SQLTimeoutException;
import java.sql.SQLTransientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionTimedOutException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * RFC 9457 problem+json for every error. Standard MVC errors (missing/mistyped params, malformed JSON, bean
 * validation, 404, 405, 415...) are handled by the base class; handleExceptionInternal() is the single place they
 * pass through, where 5xx outcomes are logged. This class deliberately declares NO catch-all
 * @ExceptionHandler(Exception.class): that lives in FallbackExceptionHandler, a separate lowest-precedence advice,
 * so the base class's own mappings can never overlap with it.
 * Technical failures map to 5xx and NEVER to an authorisation decision; SQL, hostnames and stack traces are
 * logged, never returned.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    static final String NO_DECISION = " No authorisation decision was made.";

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
                                                             HttpStatusCode statusCode, WebRequest request) {
        if (statusCode.is5xxServerError()) {
            log.error("Request failed with HTTP {}", statusCode.value(), ex);
        }
        return super.handleExceptionInternal(ex, body, headers, statusCode, request);
    }

    @ExceptionHandler(Errors.InvalidRequest.class)
    ProblemDetail invalid(Errors.InvalidRequest e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(Errors.NotFound.class)
    ProblemDetail notFound(Errors.NotFound e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler(Errors.Conflict.class)
    ProblemDetail conflict(Errors.Conflict e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, e.getMessage());
    }

    /**
     * Concurrent duplicate inserts slip past the exists-checks and hit the unique constraints. Only the two
     * known unique constraints (identified from PostgreSQL's structured error fields) mean "duplicate" (409).
     * Every other integrity failure is not the client's duplicate and is an internal error (500).
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    ProblemDetail integrity(DataIntegrityViolationException e) {
        String constraint = ConstraintViolations.uniqueConstraintName(e).orElse(null);
        if (ConstraintViolations.UQ_ISSUER_DID.equals(constraint)) {
            return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "An issuer with this DID is already registered");
        }
        if (ConstraintViolations.UQ_ISSUER_CREDENTIAL_TYPE.equals(constraint)) {
            return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT,
                "An authorisation for this issuer and credential type already exists");
        }
        log.error("Unexpected data integrity violation (unique constraint: {})", constraint, e);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error." + NO_DECISION);
    }

    /** Database down / timeout / pool exhausted -> 503; any other persistence failure -> 500. Never a decision. */
    @ExceptionHandler({DataAccessException.class, TransactionException.class})
    ProblemDetail dataStoreFailure(Exception e) {
        if (isUnavailable(e)) {
            log.error("Registry data store unavailable", e);
            return ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE,
                "The registry data store is temporarily unavailable." + NO_DECISION);
        }
        log.error("Registry persistence failure", e);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error." + NO_DECISION);
    }

    private static boolean isUnavailable(Throwable e) {
        if (e instanceof CannotCreateTransactionException || e instanceof TransactionTimedOutException
                || e instanceof TransientDataAccessException || e instanceof DataAccessResourceFailureException) {
            return true;
        }
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SQLTransientException || t instanceof SQLRecoverableException
                    || t instanceof SQLTimeoutException) {
                return true;
            }
            if (t instanceof java.sql.SQLException sql && sql.getSQLState() != null && sql.getSQLState().startsWith("08")) {
                return true;
            }
        }
        return false;
    }
}
