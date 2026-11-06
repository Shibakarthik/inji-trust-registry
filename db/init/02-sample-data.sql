-- Demonstration data (loaded by the DB init mechanism, not by application code).
-- Positive case : FarmerCredential  -> ISSUER_AUTHORIZED
-- Negative case : DrivingLicenceCredential has NO row -> CREDENTIAL_TYPE_NOT_AUTHORIZED

INSERT INTO trust.issuer (did, display_name, status)
VALUES ('did:web:Shibakarthik.github.io:collab:farmer', 'Collab Farmer Credential Issuer (test)', 'ACTIVE')
ON CONFLICT (did) DO NOTHING;

INSERT INTO trust.issuer_credential_authorization (issuer_id, credential_type, status)
SELECT id, 'FarmerCredential', 'ACTIVE'
FROM trust.issuer
WHERE did = 'did:web:Shibakarthik.github.io:collab:farmer'
ON CONFLICT (issuer_id, credential_type) DO NOTHING;
