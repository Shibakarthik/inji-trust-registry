package io.cdpi.trustregistry.domain;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = """
    Machine-readable reason for the decision.
    ISSUER_AUTHORIZED: issuer is ACTIVE and has an ACTIVE authorisation for the credential type (authorised=true).
    ISSUER_NOT_FOUND: no issuer with this identifier is registered.
    ISSUER_INACTIVE: the issuer is registered but INACTIVE.
    CREDENTIAL_TYPE_NOT_AUTHORIZED: the issuer has no authorisation record for this credential type.
    AUTHORIZATION_REVOKED: an authorisation record exists but is REVOKED.
    All codes other than ISSUER_AUTHORIZED mean authorised=false.""")
public enum ReasonCode {
    ISSUER_AUTHORIZED,
    ISSUER_NOT_FOUND,
    ISSUER_INACTIVE,
    CREDENTIAL_TYPE_NOT_AUTHORIZED,
    AUTHORIZATION_REVOKED
}
