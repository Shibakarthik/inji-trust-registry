package io.cdpi.trustregistry.dto;

import io.cdpi.trustregistry.domain.*;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public final class Dtos {
    private Dtos() { }

    @Schema(description = "Authorisation decision. Only returned for a successfully evaluated query; "
        + "technical failures are 5xx problem responses and never contain 'authorised'.")
    public record AuthorizationCheckResponse(
        @Schema(example = "did:web:example.com:issuer") String issuerId,
        @Schema(example = "FarmerCredential") String credentialType,
        @Schema(description = "true only if the issuer is ACTIVE and has an ACTIVE authorisation for the credential type")
        boolean authorised,
        ReasonCode reason,
        @Schema(description = "UTC time at which the decision was evaluated (seconds precision)",
                example = "2026-11-06T08:30:00Z") Instant evaluatedAt,
        @Schema(example = "v1") String apiVersion) { }

    public record IssuerRequest(
        @NotBlank @Size(max = 512) @Pattern(regexp = Patterns.DID_REGEX)
        @Schema(example = "did:web:example.com:issuer") String did,
        @NotBlank @Size(max = 255) @Schema(example = "Example Farmer Registry") String displayName) { }

    public record IssuerStatusRequest(@NotNull IssuerStatus status) { }

    public record IssuerResponse(String did, String displayName, IssuerStatus status,
                                 Instant createdAt, Instant updatedAt) {
        public static IssuerResponse from(Issuer i) {
            return new IssuerResponse(i.getDid(), i.getDisplayName(), i.getStatus(), i.getCreatedAt(), i.getUpdatedAt());
        }
    }

    public record AuthorizationRequest(
        @NotBlank @Pattern(regexp = Patterns.CREDENTIAL_TYPE_REGEX)
        @Schema(example = "FarmerCredential") String credentialType) { }

    public record AuthorizationResponse(String issuerId, String credentialType, AuthorizationStatus status,
                                        Instant createdAt, Instant updatedAt) {
        public static AuthorizationResponse from(IssuerCredentialAuthorization a) {
            return new AuthorizationResponse(a.getIssuer().getDid(), a.getCredentialType(), a.getStatus(),
                a.getCreatedAt(), a.getUpdatedAt());
        }
    }
}
