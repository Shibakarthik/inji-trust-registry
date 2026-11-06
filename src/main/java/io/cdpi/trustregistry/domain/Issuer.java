package io.cdpi.trustregistry.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(schema = "trust", name = "issuer")
public class Issuer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "did", nullable = false, unique = true, length = 512)
    private String did;

    @Column(name = "display_name", nullable = false, length = 255)
    private String displayName;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private IssuerStatus status = IssuerStatus.ACTIVE;

    /** Set by PostgreSQL (column DEFAULT now()); read-only for JPA. Populated by refresh after flush. */
    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    /** Maintained by the PostgreSQL BEFORE UPDATE trigger (and DEFAULT on insert); read-only for JPA. */
    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected Issuer() { }

    public Issuer(String did, String displayName) {
        this.did = did;
        this.displayName = displayName;
    }

    public Long getId() { return id; }
    public String getDid() { return did; }
    public String getDisplayName() { return displayName; }
    public IssuerStatus getStatus() { return status; }
    public void setStatus(IssuerStatus status) { this.status = status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
