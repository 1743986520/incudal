# Incudal Rust Backend (`server-rs/`)

Rust port of the Fastify + Prisma backend in `server/`. **API-compatible
strangler migration**: the Rust server talks to the exact same PostgreSQL
schema (produced by `server/prisma/migrations/`), reads the same env vars, and
must be a drop-in replacement for the TS server route by route.

The TS server in `server/` stays untouched and remains the reference. When a
route module's behavior is ambiguous, the TS source is the specification.

## Status

Ported route modules (each is a line-for-line behavior port of its TS file,
wired in `app.rs`; unmounted prefixes return `501 { code: "NOT_PORTED" }`):

| Rust module | TS source | Endpoints | Notes |
|---|---|---|---|
| `routes/auth.rs` | routes/auth.ts | 18 | login/logout/refresh/register/2FA/invites/forgot-password; email+Telegram delivery stubbed (libs/external.rs), Turnstile + GeoIP real |
| `routes/users.rs` | routes/users.ts | 21 | incl. admin user mgmt, hosting-balance adjust; also hosts shared `create_log`/`create_inbox_notification` |
| `routes/balance.rs` | routes/balance.ts | 8 | balance transfer via `balance_tx!` |
| `routes/announcements.rs` | routes/announcements.ts | 3 | |
| `routes/inbox.rs` | routes/inbox.ts | 10 | queued host-email tasks ported incl. advisory lock 4102 |
| `routes/help.rs` | routes/help.ts | 11 | |
| `routes/system_config.rs` | routes/system-config.ts | 7 | per-key validation matrix + AES-encrypted sensitive values |
| `routes/packages.rs` | routes/packages.ts | 22 | cents-based plan pricing, sold-out computation, shares, release-quota |
| `routes/ssh_keys.rs` | routes/ssh-keys.ts | 5 | `POST /generate` fails like TS when keygen unavailable (no rsa crate) |
| `routes/friends.rs` | routes/friends.ts | 11 | external channel fan-out stubbed |
| `routes/health.rs` | app.ts | 1 | |

Framework core (in `server-rs/src/`):

- `error.rs` — full `ErrorCode` + message table from `server/src/lib/errors.ts`
- `auth.rs` — JWT extractors (`AuthUser`, `AdminAuth`, `UserOnlyAuth`) mirroring
  `plugins/auth-decorators.ts`, plus `sign_access_token`
- `libs/security.rs` — refresh-token lifecycle + token invalidation
  (`refresh_tokens`, `token_invalidations` tables)
- `libs/agent_auth.rs` — HMAC auth for Go host agents (bit-compatible with
  `lib/agent-auth.ts`; canonical JSON key-sorting + JS number formatting)
- `libs/crypto.rs` — AES-256-GCM `iv:tag:ciphertext` hex format (16-byte IV!),
  TOTP (SHA1/6-digit/30s)
- `libs/validators.rs` — verbatim input validators from `lib/security.ts`
- `libs/external.rs` — Turnstile siteverify + ip-api.com GeoIP (real);
  email/Telegram senders stubbed with TODOs
- `shared_state.rs` — Redis or in-memory fallback (GETDEL/SET NX/window counters)
- `rate_limit.rs` — global 300/min + full 83-rule table from
  `config/rate-limit.ts` (declaration-order first-match semantics)
- `db.rs` — pool + advisory locks + `balance_tx!` retrying Serializable tx macro
- `response.rs` — Decimal->number (integral values print without `.0`), 
  BigInt->string, pagination helpers

## Not yet ported (roadmap, in rough priority order)

1. **instances/* route family** (instances, snapshots, instance-billing,
   instance-destroy, hourly-billing, traffic, ip-addresses, proxy-sites) — the
   core product surface. Depends on the Incus host plumbing: `lib/incus/*`
   (TLS client certs from PANEL_CRT_PATH/PANEL_KEY_PATH against host Incus
   APIs), `lib/terminal-proxy.ts` (WebSocket console), and
   `workers/instanceTaskWorker.ts` (Postgres-backed task queue with leases).
2. **hosts / admin-hosting / images / system-update / agent routes** — depend
   on the same Incus client layer plus agent credential rotation.
3. **recharge / payment webhooks** (Epay MD5/RSA, Heleket, Stripe) +
   `admin-billing` + billing-operations (90 KB of renewal/refund/destroy
   settlement logic) + official-coupons + aff + vip + checkin/redeem/resource
   pool + transfers + entertainment (lottery/badges/points) + mail hosting +
   telegram bot + oauth + verification + notifications channels.
4. **Background schedulers** (services/schedulers.ts: traffic, billing,
   expiry suspend/delete, status sync, host health) — port as tokio tasks on
   the same cadences.
5. **Production static/SPA serving** (plugins/static-server.ts) — serve
   `client/dist` with the same Cache-Control matrix and SPA fallback.
6. **Terminal WebSocket** (`/api/ws/instances/{id}/terminal`) — one-time
   tickets + Incus console proxy.
7. Email delivery (SMTP via a Rust smtp/lettre crate) to replace the
   `libs/external.rs` stubs; `rsa`/`ssh-key` crate for `POST /api/ssh-keys/generate`.

## Wire contracts (do not break these)

1. Error responses: `{ "error": <message>, "code": <code>, "details"? }`.
   Generic auth 401s from the JWT layer are bare `{ "error": "Unauthorized" }`
   (no `code`) — use `ApiError::bare`/`ApiError::unauthorized()` for those.
2. JWT: HS256, payload `{ id, username, role, sid, iat, exp }`, 30-minute
   expiry. `sid` = first 20 chars of the refresh token.
3. Refresh token: opaque `rt_<32 bytes base64url>`, stored in `refresh_tokens`,
   HttpOnly cookie named `refreshToken` (path `/`, 30-day sliding expiry,
   secure/sameSite per `Config` helpers).
4. BigInt byte counters serialize as JSON strings; Decimal money serializes as
   JSON numbers via f64 (`response::num`), matching TS `Number(decimal)`.
5. Money units: `PackagePlan.price/setupFee/trafficResetPrice` and
   `*.trafficUnitPrice` are **cents** (fen); balances/ledgers are **yuan**
   (`users.balance`, `balance_logs.*`, `instance_billing_records.amount`, ...).
6. PG enum columns: Prisma enum type names verbatim (`"UserRole"`,
   `"InstanceStatus"`); read with `role::text`, write with `$n::"UserRole"`.
7. Agent HMAC headers: `x-incudal-agent-id`, `x-incudal-timestamp` (13-digit ms),
   `x-incudal-nonce`, `x-incudal-body-sha256`, `x-incudal-signature`; signing
   payload `METHOD\npath(no query)\ntimestamp\nnonce\nbodyHash`.

## Code conventions

- axum 0.8: path params are `{param}` (not `:param`).
- State: handlers take `State(state): State<SharedAppState>` (arc of AppState).
- Auth: `_user: AuthUser` / `AdminAuth` / `UserOnlyAuth` extractors.
- Handlers return `Result<Json<Value>, ApiError>` or build `Value` and return
  `Json`. Errors: `ApiError::not_found(code::INSTANCE_NOT_FOUND)` etc.
- DB: sqlx **runtime** queries only (`sqlx::query` / `query_as` + `FromRow`
  structs). Do NOT use `query!` macros (they require a live DATABASE_URL at
  compile time). Column names are the `@map` snake_case names in
  `server/prisma/schema.prisma` — read the schema for exact columns.
- Money math: `rust_decimal::Decimal`, never f64. Convert to JSON number only
  at the response boundary with `response::num`.
- Balance/billing mutations: wrap in `balance_tx!(&state.db, tx, { ... })`
  (Serializable + retries), take advisory locks with
  `db::advisory_transaction_lock(&mut tx, db::advisory_lock_namespace::*, key)`
  mirroring the TS namespace constants.
- Rate limiting: add per-route rules to the table in `rate_limit.rs` when the
  TS route has one in `server/src/config/rate-limit.ts`.
- Route modules export `pub fn router() -> Router<SharedAppState>` with paths
  relative to their mount prefix; `app.rs` owns the prefix table.
- Validation: serde structs for bodies; reuse/extend validators in
  `libs/validators.rs` (mirroring `lib/security.ts` validatePassword/...).
- axum 0.8: path params are `{param}` (not `:param`).
- axum 0.8 has NO `IntoResponse` for raw `serde_json::Value` — status-code
  tuples must wrap the body: `(StatusCode::CREATED, axum::Json(json!({...})))`.
- Do not edit `Cargo.toml` (shared file) — if a new dependency is unavoidable,
  note it in the final report instead.
- Never invent behavior: port the TS semantics, including status codes and
  error codes. Comment where the TS has non-obvious logic.

## Checks

```bash
cargo check          # must pass
cargo test           # agent-auth canonicalization + rate limit tests
cargo run            # needs DATABASE_URL; optional REDIS_URL
```

The Rust server does NOT run Prisma migrations; schema ownership stays with
`server/prisma/migrations/` (deploy via the TS path or `prisma migrate deploy`).
