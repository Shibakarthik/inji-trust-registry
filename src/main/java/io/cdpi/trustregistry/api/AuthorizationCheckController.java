package io.cdpi.trustregistry.api;

import io.cdpi.trustregistry.dto.Dtos.AuthorizationCheckResponse;
import io.cdpi.trustregistry.dto.Patterns;
import io.cdpi.trustregistry.service.AuthorizationCheckService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public read API. "Cache-Control: no-store" is added to every response of this path (including errors) by
 * NoStoreCacheControlFilter. Access is enforced by SecurityConfig; @SecurityRequirements() below only documents it.
 */
@RestController
@RequestMapping("/v1/authorizations")
@Tag(name = "Public authorisation check", description = "Read-only, no authentication required")
public class AuthorizationCheckController {

    private final AuthorizationCheckService service;

    public AuthorizationCheckController(AuthorizationCheckService service) {
        this.service = service;
    }

    @GetMapping("/check")
    @SecurityRequirements // documentation: this operation needs no authentication
    @Operation(
        operationId = "checkAuthorization",
        summary = "Is this issuer authorised for this credential type?",
        description = """
            Public, unauthenticated, read-only (API v1). The answer is read from PostgreSQL on every call.
            authorised=true only when the issuer exists, is ACTIVE, and has an explicit ACTIVE authorisation for the
            requested credential type. Registration alone never implies authorisation for any credential type.
            Matching is exact and case-sensitive. A negative decision is HTTP 200 with authorised=false and a reason;
            a technical failure is HTTP 5xx with a problem document and NO 'authorised' field.
            Responses are never cacheable (Cache-Control: no-store).""")
    @ApiResponse(responseCode = "200",
        description = "Decision evaluated: authorised true or false (see reason)",
        content = @Content(mediaType = "application/json",
            schema = @Schema(implementation = AuthorizationCheckResponse.class),
            examples = {
                @ExampleObject(name = "authorised", value = "{\"issuerId\":\"did:web:example.com:issuer\",\"credentialType\":\"FarmerCredential\",\"authorised\":true,\"reason\":\"ISSUER_AUTHORIZED\",\"evaluatedAt\":\"2026-11-06T08:30:00Z\",\"apiVersion\":\"v1\"}"),
                @ExampleObject(name = "credentialTypeNotAuthorised", value = "{\"issuerId\":\"did:web:example.com:issuer\",\"credentialType\":\"DrivingLicenceCredential\",\"authorised\":false,\"reason\":\"CREDENTIAL_TYPE_NOT_AUTHORIZED\",\"evaluatedAt\":\"2026-11-06T08:30:00Z\",\"apiVersion\":\"v1\"}"),
                @ExampleObject(name = "unknownIssuer", value = "{\"issuerId\":\"did:web:unknown.example\",\"credentialType\":\"FarmerCredential\",\"authorised\":false,\"reason\":\"ISSUER_NOT_FOUND\",\"evaluatedAt\":\"2026-11-06T08:30:00Z\",\"apiVersion\":\"v1\"}")
            }))
    @ApiResponse(responseCode = "400", description = "Missing, blank or malformed issuerId / credentialType",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    @ApiResponse(responseCode = "500", description = "Internal error. NOT an authorisation decision.",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    @ApiResponse(responseCode = "503", description = "Registry data store unavailable or timed out. NOT an authorisation decision.",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public AuthorizationCheckResponse check(
            @Parameter(description = "Issuer DID (exact, case-sensitive)", example = "did:web:example.com:issuer", required = true)
            @RequestParam("issuerId") String issuerId,
            @Parameter(description = "Credential type (exact, case-sensitive)", example = "FarmerCredential", required = true)
            @RequestParam("credentialType") String credentialType) {
        Patterns.requireIssuerId(issuerId);
        Patterns.requireCredentialType(credentialType);
        return service.check(issuerId, credentialType);
    }
}
