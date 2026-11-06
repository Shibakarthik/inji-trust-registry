# Inji Trust Registry (CDPI assessment A.2 MVP)

Answers one question: **is issuer X currently authorised to issue credential type Y?**
The answer is read live from PostgreSQL through a public, versioned, unauthenticated read API (`/v1`).
Java 21, Spring Boot 3.4, Spring Data JPA, PostgreSQL, Maven, Springdoc OpenAPI.

## Build / test / deployment status

**Not verified by execution.** The author had no Maven, Docker or network access. The sources were checked only
for Java syntax (a parser-level `javac` pass found no syntax errors); they have **not** been compiled against their
dependencies, no test has been run, and nothing has been deployed. Run "Verify before the demonstration" and fix
whatever fails before relying on it.

## Implemented vs. future

Implemented: issuer and credential-type authorisation registry, public read API, administrator API (HTTP Basic),
OpenAPI/Swagger UI, health endpoint, SQL deployment scripts, Docker/Compose, integration tests.

Not implemented (deliberately out of A.2 scope): DID resolution or DID-document fetching, key or signature
verification, credential revocation checking, DIDComm, federation/TRQP, audit/event infrastructure, caching,
rate limiting, Certify / Mimoto / Inji Verify integration.

## Configuration (environment variables)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `POSTGRES_PASSWORD` | yes (Compose) | – | PostgreSQL password (also used by the app) |
| `POSTGRES_DB` / `POSTGRES_USER` | no | `inji_trust` / `inji_trust` | Database and role created on first start |
| `ADMIN_PASSWORD` | yes | – | Administrator password: at least 12 characters and at most 72 bytes in UTF-8 (BCrypt limit). The app refuses to start otherwise; the value is never logged. BCrypt-hashed in memory at startup |
| `ADMIN_USERNAME` | no | `admin` | Administrator user name: non-blank, no leading/trailing whitespace, no `:`, max 128 chars |
| `APP_PORT` | no | `8080` | Published port (Compose) |
| `DB_URL` / `DB_USERNAME` / `DB_PASSWORD` | app only | localhost / `inji_trust` / – | JDBC settings when running the jar without Compose (Compose sets them) |

Secrets live in `.env` (git-ignored); copy `.env.example`. Nothing secret is in source control.

## Verify before the demonstration

```bash
mvn clean verify                # Java 21 + running Docker daemon (Testcontainers starts PostgreSQL 16)
cp .env.example .env            # set strong POSTGRES_PASSWORD and ADMIN_PASSWORD
docker compose up --build -d
curl -s http://localhost:8080/actuator/health          # {"status":"UP"}
```

## Docker startup and database initialisation

`docker compose up --build -d` starts PostgreSQL and the app. PostgreSQL runs `db/init/*.sql` in name order
**only when its data volume is empty (first start)**: `01-schema.sql` (schema, constraints, indexes, `updated_at`
triggers) then `02-sample-data.sql` (demo issuer). Hibernate runs with `ddl-auto=validate`: the SQL scripts are the
only thing that shapes the schema. The database port is not published; only the app can reach it.

**Reset the sample database** (destroys ALL registry data):

```bash
docker compose down -v && docker compose up --build -d
```

## URLs and access

| URL | Access |
|---|---|
| `GET /v1/authorizations/check?issuerId=...&credentialType=...` | **public** |
| `GET /v1/openapi.json` (generated OpenAPI 3, API version `v1`) | **public** |
| `GET /swagger-ui.html` | **public** |
| `GET /actuator/health` | **public** |
| `/v1/admin/**` | **HTTP Basic**, administrator only (401 without/with wrong credentials, 403 for other roles) |
| everything else | denied |

Only the check endpoint is CORS-enabled (GET, any origin, no credentials). Sessions are stateless; CSRF protection is
off because there are no cookies or sessions (every request carries its own `Authorization` header).

## Public API

`GET /v1/authorizations/check?issuerId=<DID>&credentialType=<type>` (matching is exact and case-sensitive; inputs are
validated, never normalised):

```json
{ "issuerId": "did:web:example.com:issuer", "credentialType": "FarmerCredential", "authorised": true,
  "reason": "ISSUER_AUTHORIZED", "evaluatedAt": "2026-11-06T08:30:00Z", "apiVersion": "v1" }
```

Decision order: issuer exists? -> issuer ACTIVE? -> authorisation mapping exists? -> mapping ACTIVE?

| `reason` | `authorised` | Meaning |
|---|---|---|
| `ISSUER_AUTHORIZED` | true | issuer ACTIVE and its mapping for this credential type ACTIVE |
| `ISSUER_NOT_FOUND` | false | no issuer with this exact DID |
| `ISSUER_INACTIVE` | false | issuer registered but INACTIVE |
| `CREDENTIAL_TYPE_NOT_AUTHORIZED` | false | no mapping for this credential type (registration never implies authorisation) |
| `AUTHORIZATION_REVOKED` | false | mapping exists but is REVOKED |

**Negative decisions vs. technical failures.** A negative decision is HTTP **200** with `authorised: false` and a
reason. A technical failure is never a decision: invalid input -> **400**; database unavailable or timed out -> **503**;
any other internal error -> **500**. Error bodies are RFC 9457 `application/problem+json`, contain no `authorised`
field and no SQL, hostnames or stack traces. Every response of the check endpoint (success and error) carries
`Cache-Control: no-store`.

```bash
BASE=http://localhost:8080
curl -s "$BASE/v1/authorizations/check?issuerId=did:web:Shibakarthik.github.io:collab:farmer&credentialType=FarmerCredential"          # ISSUER_AUTHORIZED
curl -s "$BASE/v1/authorizations/check?issuerId=did:web:Shibakarthik.github.io:collab:farmer&credentialType=DrivingLicenceCredential" # CREDENTIAL_TYPE_NOT_AUTHORIZED
curl -s "$BASE/v1/authorizations/check?issuerId=did:web:unknown.example&credentialType=FarmerCredential"                              # ISSUER_NOT_FOUND
curl -si "$BASE/v1/authorizations/check?issuerId=did:web:example.com:issuer" | head -1                                                # 400
```

## Administration API (HTTP Basic)

| Operation | Endpoint | Success | Errors |
|---|---|---|---|
| Register issuer (created ACTIVE, **no** authorisations) | `POST /v1/admin/issuers` `{"did","displayName"}` | 201 | 400, 409 duplicate DID |
| Get issuer | `GET /v1/admin/issuers/{issuerId}` | 200 | 404 |
| List issuers | `GET /v1/admin/issuers?status=&page=&size=` | 200 | 400 |
| Activate / deactivate issuer (idempotent) | `PATCH /v1/admin/issuers/{issuerId}/status` `{"status":"ACTIVE\|INACTIVE"}` | 200 | 400, 404 |
| Authorise issuer for credential type | `POST /v1/admin/issuers/{issuerId}/authorizations` `{"credentialType"}` | 201 | 400, 404, **409 if it already exists (active *or revoked*)** |
| Issuer's authorisations (incl. revoked) | `GET /v1/admin/issuers/{issuerId}/authorizations` | 200 | 404 |
| List/filter authorisations | `GET /v1/admin/authorizations?issuerId=&credentialType=&status=&page=&size=` | 200 | 400 |
| Revoke (idempotent) | `POST /v1/admin/issuers/{issuerId}/authorizations/{credentialType}/revoke` | 200, updated representation | 404 |
| Reactivate (idempotent) | `POST /v1/admin/issuers/{issuerId}/authorizations/{credentialType}/reactivate` | 200, updated representation | 404 |

Important: **creating** an authorisation that already exists, including a revoked one, returns **409** and never
reactivates it. A revoked authorisation must be restored explicitly with `/reactivate`. Revoking only sets
`status=REVOKED`; authorisation records are never deleted. Pagination: `page >= 0`, `1 <= size <= 200`.

```bash
ADMIN='-u admin:<ADMIN_PASSWORD>'; J='-H Content-Type:application/json'; D=did:web:example.com:issuer
curl -s $ADMIN $J -X POST $BASE/v1/admin/issuers -d "{\"did\":\"$D\",\"displayName\":\"Example Issuer\"}"
curl -s $ADMIN $J -X POST $BASE/v1/admin/issuers/$D/authorizations -d '{"credentialType":"FarmerCredential"}'
curl -s $ADMIN -X POST $BASE/v1/admin/issuers/$D/authorizations/FarmerCredential/revoke
curl -s $ADMIN -X POST $BASE/v1/admin/issuers/$D/authorizations/FarmerCredential/reactivate
curl -s $ADMIN $J -X PATCH $BASE/v1/admin/issuers/$D/status -d '{"status":"INACTIVE"}'
```

## Live demonstration sequence

1. `GET /actuator/health` is UP; `GET /v1/openapi.json` (`info.version` = `v1`) and Swagger UI load without credentials.
2. The panel picks any issuer DID and credential type and queries the public endpoint from its own client -> `ISSUER_NOT_FOUND`.
3. Administrator registers that issuer -> query again -> `CREDENTIAL_TYPE_NOT_AUTHORIZED`.
4. Administrator authorises the credential type -> `authorised: true`.
5. Administrator revokes it -> `AUTHORIZATION_REVOKED`; reactivates -> `authorised: true`.
6. Administrator deactivates the issuer -> `ISSUER_INACTIVE`; reactivates the issuer.
7. `GET /v1/admin/issuers` without credentials -> 401.

## Database schema (db/init/01-schema.sql)

- `trust.issuer`: `id` identity PK; `did` VARCHAR(512) NOT NULL, **UNIQUE** (`uq_issuer_did`); `display_name` VARCHAR(255);
  `status` CHECK IN (`ACTIVE`,`INACTIVE`); `created_at`, `updated_at` TIMESTAMPTZ.
- `trust.issuer_credential_authorization`: `id` identity PK; `issuer_id` FK -> `issuer(id)` **ON DELETE RESTRICT**;
  `credential_type` VARCHAR(128); `status` CHECK IN (`ACTIVE`,`REVOKED`); timestamps;
  **UNIQUE (`issuer_id`,`credential_type`)** (`uq_issuer_credential_type`, also serves the check query).
- Index `idx_authorization_credential_type` for filtering by credential type. DID lookup uses the unique index.
- `BEFORE UPDATE` triggers keep `updated_at` current on both tables.
- Entities map explicitly to schema `trust`.
- **Timestamps:** PostgreSQL is the only source of `created_at`/`updated_at` (column defaults and the `BEFORE UPDATE`
  triggers, so direct SQL updates are covered too). JPA maps both columns read-only; after each admin write the service
  flushes and reloads the row, so API responses carry exactly the persisted values.
- **Duplicate protection:** the unique constraints are the final guard; the service pre-checks for friendly errors. A
  concurrent duplicate that slips past the pre-check is identified from PostgreSQL's structured error fields (SQLSTATE
  `23505` + constraint name, via the pgjdbc `ServerErrorMessage`, not message text). Only `uq_issuer_did` and
  `uq_issuer_credential_type` map to 409; every other integrity violation is a 500.

## Error handling

`GlobalExceptionHandler` (extends `ResponseEntityExceptionHandler`; standard MVC errors and a single 5xx logging hook in
`handleExceptionInternal`) handles the application's specific exceptions. The catch-all for unexpected exceptions is a
separate lowest-precedence advice (`FallbackExceptionHandler`), so no handler mapping overlaps. Responses are always
`application/problem+json`; 401/403 come from the security layer in the same format.

## Context path

If the app is deployed under a context path (`server.servlet.context-path`), the paths in this README are relative to
it. The `no-store` filter, security rules and MVC mappings all work relative to the context path.

## HTTPS

The app serves plain HTTP on 8080 and honours `X-Forwarded-*` headers. Terminate TLS in front of it, e.g. Caddy:

```
registry.example.org {
    reverse_proxy app:8080
}
```

## Known limitations

- Single PostgreSQL role owns the tables and is used by the app. For production use separate owner/migration and
  least-privilege app roles.
- Single administrator account from environment variables; no audit trail or rate limiting.
- Browsers that cache HTTP Basic credentials would send them to the admin endpoints automatically; use the admin API
  from non-browser clients or behind a network boundary.

## Layout

```
db/init/            01-schema.sql, 02-sample-data.sql
src/main/java/...   config/ domain/ repository/ service/ dto/ error/ api/
src/test/java/...   Testcontainers integration tests + unit tests
Dockerfile, docker-compose.yml, .env.example
```
