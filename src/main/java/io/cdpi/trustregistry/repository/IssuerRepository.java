package io.cdpi.trustregistry.repository;

import io.cdpi.trustregistry.domain.Issuer;
import io.cdpi.trustregistry.domain.IssuerStatus;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IssuerRepository extends JpaRepository<Issuer, Long> {

    Optional<Issuer> findByDid(String did);

    boolean existsByDid(String did);

    Page<Issuer> findByStatus(IssuerStatus status, Pageable pageable);
}
