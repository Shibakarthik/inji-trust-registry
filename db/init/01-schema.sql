-- Inji Trust Registry: schema (A.2 MVP). Runs once on first start of an empty PostgreSQL volume.
-- The database (inji_trust) is created by the container via POSTGRES_DB.
-- Hibernate runs with ddl-auto=validate: this script is the only thing that shapes the schema.

CREATE SCHEMA IF NOT EXISTS trust;

CREATE TABLE trust.issuer (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    did           VARCHAR(512) NOT NULL,
    display_name  VARCHAR(255) NOT NULL,
    status        VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_issuer_did    UNIQUE (did),
    CONSTRAINT ck_issuer_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

CREATE TABLE trust.issuer_credential_authorization (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer_id        BIGINT       NOT NULL REFERENCES trust.issuer (id) ON DELETE RESTRICT,
    credential_type  VARCHAR(128) NOT NULL,
    status           VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- one record per issuer + credential type; also the index serving the public check query
    CONSTRAINT uq_issuer_credential_type UNIQUE (issuer_id, credential_type),
    CONSTRAINT ck_authorization_status   CHECK (status IN ('ACTIVE', 'REVOKED'))
);

-- "which issuers are authorised for credential type X" (list/filter queries)
CREATE INDEX idx_authorization_credential_type ON trust.issuer_credential_authorization (credential_type);

-- keep updated_at correct even for changes made directly in SQL
CREATE OR REPLACE FUNCTION trust.set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_issuer_updated_at
    BEFORE UPDATE ON trust.issuer
    FOR EACH ROW EXECUTE FUNCTION trust.set_updated_at();

CREATE TRIGGER trg_authorization_updated_at
    BEFORE UPDATE ON trust.issuer_credential_authorization
    FOR EACH ROW EXECUTE FUNCTION trust.set_updated_at();
