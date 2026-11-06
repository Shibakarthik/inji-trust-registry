package io.cdpi.trustregistry.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(schema = "trust", name = "issuer_credential_authorization")
public class IssuerCredentialAuthorization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "issuer_id", nullable = false)
    private Issuer issuer;

    @Column(name = "credential_type", nullable = false, length = 128)
    private String credentialType;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private AuthorizationStatus status = AuthorizationStatus.ACTIVE;

    /** Set by PostgreSQL (column DEFAULT now()); read-only for JPA. */
    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    /** Maintained by the PostgreSQL BEFORE UPDATE trigger; read-only for JPA. */
    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected IssuerCredentialAuthorization() { }

    public IssuerCredentialAuthorization(Issuer issuer, String credentialType) {
        this.issuer = issuer;
        this.credentialType = credentialType;
    }

    public Long getId() { return id; }
    public Issuer getIssuer() { return issuer; }
    public String getCredentialType() { return credentialType; }
    public AuthorizationStatus getStatus() { return status; }
    public void setStatus(AuthorizationStatus status) { this.status = status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
