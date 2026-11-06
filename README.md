# Inji Trust Registry (CDPI assessment A.2 MVP)

Answers one question: **is issuer X currently authorised to issue credential type Y?**
The answer is read live from PostgreSQL through a public, versioned, unauthenticated read API (`/v1`).
Java 21, Spring Boot 3.4, Spring Data JPA, PostgreSQL, Maven, Springdoc OpenAPI.

## Build / test / deployment status

**Not verified by execution in this environment.** Run the CI workflow and the local verification commands below before relying on this for a formal demonstration. A green CI run is required before merging.

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
| `ADMIN_PASSWORD` | yes | – | Administrator password: at least 12 characters and at most 72 bytes in UTF-8 (BCrypt limit). The app refuses to start otherwise |
| `ADMIN_USERNAME` | no | `admin` | Administrator user name: non-blank, no leading/trailing whitespace, no `:`, max 128 chars |
| `APP_PORT` | no | `8080` | Published port (Compose) |
| `DB_URL` / `DB_USERNAME` / `DB_PASSWORD` | app only | localhost / `inji_trust` / – | JDBC settings when running the jar without Compose (Compose sets them) |

Secrets live in `.env` (git-ignored); copy `.env.example`. Nothing secret is in source control.

## Verify before the demonstration

Requirements: Java 21, Maven 3.9+, Docker Engine with Compose plugin, and a running Docker daemon (Testcontainers uses Docker).

```bash
mvn clean verify
cp .env.example .env
# Edit .env: set strong, unique POSTGRES_PASSWORD and ADMIN_PASSWORD values.
docker compose up --build -d
docker compose ps
curl -fsS http://localhost:8080/actuator/health
```

The Maven verification runs the integration suite against PostgreSQL 16 using Testcontainers. The Compose health endpoint must return `{"status":"UP"}`.

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
| `/v1/admin/**` | **HTTP Basic**, administrator only |
| everything else | denied |

Only the public check endpoint is CORS-enabled (GET, any origin, no credentials). Sessions are stateless.
Every state-changing admin request (POST/PUT/PATCH/DELETE) must include both valid HTTP Basic credentials and
`X-Registry-Admin-Request: true`. This non-simple custom header is a CSRF defence: browser forms cannot send it,
and cross-origin JavaScript cannot send it without a preflight; admin routes do not allow CORS. Admin endpoints
are intended for non-browser clients. Do not remove this header requirement while keeping HTTP Basic authentication.

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
curl -s "$BASE/v1/authorizations/check?issuerId=did:web:Shibakarthik.github.io:collab:farmer&credentialType=FarmerCredential"
curl -s "$BASE/v1/authorizations/check?issuerId=did:web:Shibakarthik.github.io:collab:farmer&credentialType=DrivingLicenceCredential"
curl -s "$BASE/v1/authorizations/check?issuerId=did:web:unknown.example&credentialType=FarmerCredential"
curl -si "$BASE/v1/authorizations/check?issuerId=did:web:example.com:issuer" | head -1
```

## Administration API (HTTP Basic)

For shell examples, define credentials and the required request header once:

```bash
ADMIN=(-u "admin:<ADMIN_PASSWORD>" -H "X-Registry-Admin-Request: true")
J=(-H "Content-Type: application/json")
D='did:web:example.com:issuer'
```

| Operation | Endpoint | Success | Errors |
|---|---|---|---|
| Register issuer (created ACTIVE, **no** authorisations) | `POST /v1/admin/issuers` `{"did","displayName"}` | 201 | 400, 409 duplicate DID |
| Get issuer | `GET /v1/admin/issuers/{issuerId}` | 200 | 404 |
| List issuers | `GET /v1/admin/issuers?status=&page=&size=` | 200 | 400 |
| Activate / deactivate issuer | `PATCH /v1/admin/issuers/{issuerId}/status` `{"status":"ACTIVE|INACTIVE"}` | 200 | 400, 404 |
| Authorise issuer for credential type | `POST /v1/admin/issuers/{issuerId}/authorizations` `{"credentialType"}` | 201 | 400, 404, 409 duplicate |
| Issuer's authorisations | `GET /v1/admin/issuers/{issuerId}/authorizations` | 200 | 404 |
| List/filter authorisations | `GET /v1/admin/authorizations?issuerId=&credentialType=&status=&page=&size=` | 200 | 400 |
| Revoke | `POST /v1/admin/issuers/{issuerId}/authorizations/{credentialType}/revoke` | 200 | 404 |
| Reactivate | `POST /v1/admin/issuers/{issuerId}/authorizations/{credentialType}/reactivate` | 200 | 404 |

Creating an existing authorisation (active or revoked) returns 409; a revoked authorisation must be explicitly reactivated.
Revocation keeps the row. Pagination: `page >= 0`, `1 <= size <= 200`.

```bash
curl -s "${ADMIN[@]}" "${J[@]}" -X POST "$BASE/v1/admin/issuers" -d "{\"did\":\"$D\",\"displayName\":\"Example Issuer\"}"
curl -s "${ADMIN[@]}" "${J[@]}" -X POST "$BASE/v1/admin/issuers/$D/authorizations" -d '{"credentialType":"FarmerCredential"}'
curl -s "${ADMIN[@]}" -X POST "$BASE/v1/admin/issuers/$D/authorizations/FarmerCredential/revoke"
curl -s "${ADMIN[@]}" "${J[@]}" -X POST "$BASE/v1/admin/issuers/$D/authorizations/FarmerCredential/reactivate"
curl -s "${ADMIN[@]}" "${J[@]}" -X PATCH "$BASE/v1/admin/issuers/$D/status" -d '{"status":"INACTIVE"}'
```

## Live demonstration sequence

1. Health is UP; OpenAPI and Swagger UI load without credentials.
2. Query an unknown issuer and credential type -> `ISSUER_NOT_FOUND`.
3. Register the issuer -> `CREDENTIAL_TYPE_NOT_AUTHORIZED`.
4. Authorise the credential type -> `authorised: true`.
5. Revoke -> `AUTHORIZATION_REVOKED`; reactivate -> `authorised: true`.
6. Deactivate the issuer -> `ISSUER_INACTIVE`; reactivate the issuer.
7. Admin GET without credentials -> 401; admin POST without the custom header -> 403.

## HTTPS

The app serves plain HTTP on 8080 and honours `X-Forwarded-*` headers. Terminate TLS in front of it, e.g. Caddy.

## Known limitations

- Single PostgreSQL role owns the tables and is used by the app; production should separate owner/migration and least-privilege app roles.
- Single administrator account from environment variables; no audit trail or rate limiting.
- Admin API is intentionally designed for non-browser clients; unsafe requests require the custom anti-CSRF header.

## Layout

```
db/init/            01-schema.sql, 02-sample-data.sql
src/main/java/...   config/ domain/ repository/ service/ dto/ error/ api/
src/test/java/...   Testcontainers integration tests + unit tests
.github/workflows/  Maven CI
Dockerfile, docker-compose.yml, .env.example
```
