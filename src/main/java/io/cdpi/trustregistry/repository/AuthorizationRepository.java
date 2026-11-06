package io.cdpi.trustregistry.repository;

import io.cdpi.trustregistry.domain.AuthorizationStatus;
import io.cdpi.trustregistry.domain.IssuerCredentialAuthorization;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuthorizationRepository
        extends JpaRepository<IssuerCredentialAuthorization, Long>,
                JpaSpecificationExecutor<IssuerCredentialAuthorization> {

    /** Hot path of the public check; served by the unique (issuer_id, credential_type) index. */
    @Query("select a.status from IssuerCredentialAuthorization a "
         + "where a.issuer.id = :issuerId and a.credentialType = :credentialType")
    Optional<AuthorizationStatus> findStatus(@Param("issuerId") Long issuerId,
                                             @Param("credentialType") String credentialType);

    Optional<IssuerCredentialAuthorization> findByIssuerIdAndCredentialType(Long issuerId, String credentialType);

    boolean existsByIssuerIdAndCredentialType(Long issuerId, String credentialType);

    List<IssuerCredentialAuthorization> findByIssuerIdOrderByCredentialType(Long issuerId);

    @Override
    @EntityGraph(attributePaths = "issuer")
    Page<IssuerCredentialAuthorization> findAll(Specification<IssuerCredentialAuthorization> spec, Pageable pageable);
}
