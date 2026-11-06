package io.cdpi.trustregistry.api;

import io.cdpi.trustregistry.domain.AuthorizationStatus;
import io.cdpi.trustregistry.domain.IssuerStatus;
import io.cdpi.trustregistry.dto.Dtos.*;
import io.cdpi.trustregistry.service.RegistryAdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.*;

/** Administration API. Access is enforced by SecurityConfig (/v1/admin/** requires ROLE_REGISTRY_ADMIN via HTTP Basic). */
@RestController
@RequestMapping("/v1/admin")
@Tag(name = "Administration", description = "Requires administrator credentials (HTTP Basic)")
@SecurityRequirement(name = "basicAuth")
@ApiResponse(responseCode = "400", description = "Invalid request (body, path or query parameter)",
    content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
@ApiResponse(responseCode = "401", description = "Missing or invalid administrator credentials",
    content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
@ApiResponse(responseCode = "403", description = "Authenticated but not an administrator",
    content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
@ApiResponse(responseCode = "500", description = "Internal error",
    content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
@ApiResponse(responseCode = "503", description = "Registry data store unavailable or timed out",
    content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
public class AdminController {

    private final RegistryAdminService service;

    public AdminController(RegistryAdminService service) {
        this.service = service;
    }

    // ---- issuers ----

    @PostMapping("/issuers")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register an issuer",
        description = "Creates the issuer as ACTIVE with NO credential-type authorisations. HTTP 409 if the DID is already registered.")
    @ApiResponse(responseCode = "201", description = "Issuer registered")
    @ApiResponse(responseCode = "409", description = "Issuer already registered",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public IssuerResponse registerIssuer(@Valid @RequestBody IssuerRequest request) {
        return service.registerIssuer(request);
    }

    @GetMapping("/issuers")
    @Operation(summary = "List issuers", description = "page >= 0, 1 <= size <= 200, ordered by creation.")
    public List<IssuerResponse> listIssuers(@RequestParam(required = false) IssuerStatus status,
                                            @RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "50") int size) {
        return service.listIssuers(status, page, size);
    }

    @GetMapping("/issuers/{issuerId}")
    @Operation(summary = "Retrieve an issuer")
    @ApiResponse(responseCode = "404", description = "Issuer not found",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public IssuerResponse getIssuer(@PathVariable String issuerId) {
        return service.getIssuer(issuerId);
    }

    @PatchMapping("/issuers/{issuerId}/status")
    @Operation(summary = "Activate or deactivate an issuer",
        description = "Idempotent. An INACTIVE issuer is never authorised, whatever its credential-type authorisations say.")
    @ApiResponse(responseCode = "404", description = "Issuer not found",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public IssuerResponse setIssuerStatus(@PathVariable String issuerId,
                                          @Valid @RequestBody IssuerStatusRequest request) {
        return service.setIssuerStatus(issuerId, request.status());
    }

    // ---- authorisations ----

    @PostMapping("/issuers/{issuerId}/authorizations")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Authorise an issuer for a credential type",
        description = """
            New authorisation: 201 Created (status ACTIVE).
            An authorisation for this issuer + credential type already exists (ACTIVE or REVOKED): 409 Conflict.
            This operation never reactivates anything: to restore a REVOKED authorisation the administrator must
            explicitly call the reactivate endpoint.""")
    @ApiResponse(responseCode = "201", description = "Authorisation created (ACTIVE)")
    @ApiResponse(responseCode = "404", description = "Issuer not found",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    @ApiResponse(responseCode = "409", description = "Authorisation already exists (active or revoked); use /reactivate for a revoked one",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public AuthorizationResponse authorize(@PathVariable String issuerId,
                                           @Valid @RequestBody AuthorizationRequest request) {
        return service.authorize(issuerId, request.credentialType());
    }

    @GetMapping("/issuers/{issuerId}/authorizations")
    @Operation(summary = "Retrieve an issuer's authorisations (including revoked ones)")
    @ApiResponse(responseCode = "404", description = "Issuer not found",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public List<AuthorizationResponse> listForIssuer(@PathVariable String issuerId) {
        return service.listForIssuer(issuerId);
    }

    @GetMapping("/authorizations")
    @Operation(summary = "List authorisations, optionally filtered", description = "page >= 0, 1 <= size <= 200.")
    public List<AuthorizationResponse> listAuthorizations(@RequestParam(required = false) String issuerId,
                                                          @RequestParam(required = false) String credentialType,
                                                          @RequestParam(required = false) AuthorizationStatus status,
                                                          @RequestParam(defaultValue = "0") int page,
                                                          @RequestParam(defaultValue = "50") int size) {
        return service.listAuthorizations(issuerId, credentialType, status, page, size);
    }

    @PostMapping("/issuers/{issuerId}/authorizations/{credentialType}/revoke")
    @Operation(summary = "Revoke an authorisation",
        description = "Sets status to REVOKED; the record is kept. Idempotent: revoking an already revoked authorisation returns 200 with the unchanged representation.")
    @ApiResponse(responseCode = "200", description = "Updated authorisation representation (status REVOKED)")
    @ApiResponse(responseCode = "404", description = "Issuer or authorisation not found",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public AuthorizationResponse revoke(@PathVariable String issuerId, @PathVariable String credentialType) {
        return service.setAuthorizationStatus(issuerId, credentialType, AuthorizationStatus.REVOKED);
    }

    @PostMapping("/issuers/{issuerId}/authorizations/{credentialType}/reactivate")
    @Operation(summary = "Reactivate a revoked authorisation",
        description = "Sets status to ACTIVE. Idempotent: reactivating an already active authorisation returns 200 with the unchanged representation.")
    @ApiResponse(responseCode = "200", description = "Updated authorisation representation (status ACTIVE)")
    @ApiResponse(responseCode = "404", description = "Issuer or authorisation not found",
        content = @Content(mediaType = "application/problem+json", schema = @Schema(implementation = ProblemDetail.class)))
    public AuthorizationResponse reactivate(@PathVariable String issuerId, @PathVariable String credentialType) {
        return service.setAuthorizationStatus(issuerId, credentialType, AuthorizationStatus.ACTIVE);
    }
}
