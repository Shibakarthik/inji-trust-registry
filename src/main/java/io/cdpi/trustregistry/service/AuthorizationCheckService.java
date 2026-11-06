package io.cdpi.trustregistry.service;

import io.cdpi.trustregistry.domain.*;
import io.cdpi.trustregistry.dto.Dtos.AuthorizationCheckResponse;
import io.cdpi.trustregistry.dto.Patterns;
import io.cdpi.trustregistry.repository.AuthorizationRepository;
import io.cdpi.trustregistry.repository.IssuerRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Evaluates the decision purely from database rows. Any database problem surfaces as an exception
 * (mapped to 5xx by GlobalExceptionHandler); there is no code path that turns an error into authorised=false.
 */
@Service
public class AuthorizationCheckService {

    public static final String API_VERSION = "v1";

    private final IssuerRepository issuers;
    private final AuthorizationRepository authorizations;
    private final Clock clock;

    public AuthorizationCheckService(IssuerRepository issuers, AuthorizationRepository authorizations, Clock clock) {
        this.issuers = issuers;
        this.authorizations = authorizations;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public AuthorizationCheckResponse check(String issuerId, String credentialType) {
        Patterns.requireIssuerId(issuerId);
        Patterns.requireCredentialType(credentialType);
        ReasonCode reason = evaluate(issuerId, credentialType);
        return new AuthorizationCheckResponse(
            issuerId, credentialType,
            reason == ReasonCode.ISSUER_AUTHORIZED,
            reason,
            clock.instant().truncatedTo(ChronoUnit.SECONDS),
            API_VERSION);
    }

    private ReasonCode evaluate(String issuerId, String credentialType) {
        Optional<Issuer> issuer = issuers.findByDid(issuerId);
        if (issuer.isEmpty()) {
            return ReasonCode.ISSUER_NOT_FOUND;
        }
        if (issuer.get().getStatus() != IssuerStatus.ACTIVE) {
            return ReasonCode.ISSUER_INACTIVE;
        }
        Optional<AuthorizationStatus> status = authorizations.findStatus(issuer.get().getId(), credentialType);
        if (status.isEmpty()) {
            return ReasonCode.CREDENTIAL_TYPE_NOT_AUTHORIZED;
        }
        return status.get() == AuthorizationStatus.ACTIVE
            ? ReasonCode.ISSUER_AUTHORIZED
            : ReasonCode.AUTHORIZATION_REVOKED;
    }
}
