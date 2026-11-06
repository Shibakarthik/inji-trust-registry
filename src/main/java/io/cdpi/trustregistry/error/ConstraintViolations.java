package io.cdpi.trustregistry.error;

import java.util.Optional;
import org.postgresql.util.PSQLException;
import org.postgresql.util.ServerErrorMessage;

/**
 * Identifies WHICH unique constraint a persistence exception violated, using the structured fields PostgreSQL
 * sends with the error (SQLSTATE 23505 and the constraint-name field), not the human-readable message text.
 */
public final class ConstraintViolations {
    private ConstraintViolations() { }

    public static final String UQ_ISSUER_DID = "uq_issuer_did";
    public static final String UQ_ISSUER_CREDENTIAL_TYPE = "uq_issuer_credential_type";

    static final String UNIQUE_VIOLATION = "23505";

    /** Returns the violated unique constraint's name, or empty if the failure is not a unique violation. */
    public static Optional<String> uniqueConstraintName(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof PSQLException pe) {
                ServerErrorMessage server = pe.getServerErrorMessage();
                if (server != null && UNIQUE_VIOLATION.equals(server.getSQLState()) && server.getConstraint() != null) {
                    return Optional.of(server.getConstraint());
                }
            }
        }
        // Fallback for a layer that exposes the same metadata without the driver exception in the chain.
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof org.hibernate.exception.ConstraintViolationException h
                    && UNIQUE_VIOLATION.equals(h.getSQLState()) && h.getConstraintName() != null) {
                return Optional.of(h.getConstraintName());
            }
        }
        return Optional.empty();
    }
}
