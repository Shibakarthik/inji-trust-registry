package io.cdpi.trustregistry.service;

import io.cdpi.trustregistry.domain.*;
import io.cdpi.trustregistry.dto.Dtos.*;
import io.cdpi.trustregistry.dto.Patterns;
import io.cdpi.trustregistry.error.Errors;
import io.cdpi.trustregistry.repository.AuthorizationRepository;
import io.cdpi.trustregistry.repository.IssuerRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RegistryAdminService {

    private final IssuerRepository issuers;
    private final AuthorizationRepository authorizations;

    @PersistenceContext
    private EntityManager em;

    public RegistryAdminService(IssuerRepository issuers, AuthorizationRepository authorizations) {
        this.issuers = issuers;
        this.authorizations = authorizations;
    }

    // ---- issuers ----

    @Transactional
    public IssuerResponse registerIssuer(IssuerRequest req) {
        Patterns.requireIssuerId(req.did());
        Patterns.requireDisplayName(req.displayName());
        if (issuers.existsByDid(req.did())) {
            throw new Errors.Conflict("Issuer already registered: " + req.did());
        }
        // A concurrent duplicate passes the check above and is stopped by uq_issuer_did (-> 409 in the API layer).
        return IssuerResponse.from(persisted(issuers.saveAndFlush(new Issuer(req.did(), req.displayName()))));
    }

    @Transactional(readOnly = true)
    public IssuerResponse getIssuer(String did) {
        return IssuerResponse.from(requireIssuer(did));
    }

    @Transactional(readOnly = true)
    public List<IssuerResponse> listIssuers(IssuerStatus status, int page, int size) {
        Pageable p = pageable(page, size, "id");
        var result = status == null ? issuers.findAll(p) : issuers.findByStatus(status, p);
        return result.stream().map(IssuerResponse::from).toList();
    }

    @Transactional
    public IssuerResponse setIssuerStatus(String did, IssuerStatus status) {
        Issuer issuer = requireIssuer(did);
        issuer.setStatus(status); // idempotent: an unchanged status issues no UPDATE
        return IssuerResponse.from(persisted(issuer));
    }

    // ---- authorisations ----

    @Transactional
    public AuthorizationResponse authorize(String did, String credentialType) {
        Patterns.requireCredentialType(credentialType);
        Issuer issuer = requireIssuer(did);
        if (authorizations.existsByIssuerIdAndCredentialType(issuer.getId(), credentialType)) {
            throw new Errors.Conflict("Authorisation already exists for " + did + " / " + credentialType
                + " (use revoke / reactivate to change its status)");
        }
        // A concurrent duplicate is stopped by uq_issuer_credential_type (-> 409 in the API layer).
        return AuthorizationResponse.from(persisted(
            authorizations.saveAndFlush(new IssuerCredentialAuthorization(issuer, credentialType))));
    }

    @Transactional(readOnly = true)
    public List<AuthorizationResponse> listForIssuer(String did) {
        Issuer issuer = requireIssuer(did);
        return authorizations.findByIssuerIdOrderByCredentialType(issuer.getId())
            .stream().map(AuthorizationResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public List<AuthorizationResponse> listAuthorizations(String issuerId, String credentialType,
                                                          AuthorizationStatus status, int page, int size) {
        // Optional filters are validated when supplied (malformed or blank -> 400). Values are never normalised.
        if (issuerId != null) {
            Patterns.requireIssuerId(issuerId);
        }
        if (credentialType != null) {
            Patterns.requireCredentialType(credentialType);
        }
        Pageable pageable = pageable(page, size, "id");
        Specification<IssuerCredentialAuthorization> spec = Specification.where(null);
        if (issuerId != null) {
            spec = spec.and((r, q, cb) -> cb.equal(r.get("issuer").get("did"), issuerId));
        }
        if (credentialType != null) {
            spec = spec.and((r, q, cb) -> cb.equal(r.get("credentialType"), credentialType));
        }
        if (status != null) {
            spec = spec.and((r, q, cb) -> cb.equal(r.get("status"), status));
        }
        return authorizations.findAll(spec, pageable).stream().map(AuthorizationResponse::from).toList();
    }

    /** Revoke (REVOKED) or reactivate (ACTIVE). Idempotent: re-applying the current status is a no-op 200. */
    @Transactional
    public AuthorizationResponse setAuthorizationStatus(String did, String credentialType, AuthorizationStatus status) {
        Patterns.requireCredentialType(credentialType);
        Issuer issuer = requireIssuer(did);
        IssuerCredentialAuthorization auth = authorizations
            .findByIssuerIdAndCredentialType(issuer.getId(), credentialType)
            .orElseThrow(() -> new Errors.NotFound("No authorisation for " + did + " / " + credentialType));
        auth.setStatus(status);
        return AuthorizationResponse.from(persisted(auth));
    }

    // ---- helpers ----

    /**
     * created_at/updated_at are produced by PostgreSQL (column defaults and the BEFORE UPDATE triggers). Flush any
     * pending change, then reload the row so the returned representation carries the values actually persisted.
     */
    private <T> T persisted(T entity) {
        em.flush();
        em.refresh(entity);
        return entity;
    }

    private Issuer requireIssuer(String did) {
        Patterns.requireIssuerId(did);
        return issuers.findByDid(did).orElseThrow(() -> new Errors.NotFound("Issuer not found: " + did));
    }

    private static Pageable pageable(int page, int size, String sortProperty) {
        if (page < 0 || size < 1 || size > 200) {
            throw new Errors.InvalidRequest("page must be >= 0 and size must be between 1 and 200");
        }
        return PageRequest.of(page, size, Sort.by(sortProperty));
    }
}
