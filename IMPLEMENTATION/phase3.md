# PHASE 3 — Authentication, User Sync, Webhooks, Free-Tier Limits

> **For OpenCode.** Prerequisites: Phase 1 and Phase 2 finished (all boxes ticked, both test suites green, DB running).
> Companion: `DATABASE-DESIGN.md` (no schema changes in this phase — the tables already exist).
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`. Never write Python.**

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]` here, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. Do NOT read the whole repo. Read only files a task names (`sed -n`, `head -n 60`).
3. Pipe long output through `tail -n 20`. Run tests with `--reporter=dot`.
4. Fetch a skill/doc ONLY when a task says so; read only the named file.
5. One commit per task, message given in the task.
6. If verification fails twice → stop, report the exact error, do not redesign.
7. **NEVER print, log, commit or echo secret values** (`CLERK_SECRET_KEY`, `CLERK_WEBHOOK_SIGNING_SECRET`, any JWT). Secrets live only in `server/.env` (gitignored). If you need the user to provide one, ASK and wait.

### 0.1 Skill / reference registry (all verified to exist)

```bash
git clone --depth 1 https://github.com/clerk/skills /tmp/skills-clerk
ls /tmp/skills-clerk/skills/core                      # core/clerk = the router skill (read its SKILL.md first)
curl -s https://clerk.com/.well-known/agent-skills/index.json | head -c 3000   # full catalog of Clerk skills
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina   # skills/node/rules/{error-handling,testing,logging}.md
git clone --depth 1 https://github.com/prisma/skills /tmp/skills-prisma       # prisma-client-api (raw queries)
```

| Short name | URL |
|---|---|
| CLERK-SKILLS-DOC | https://clerk.com/docs/guides/ai/skills.md |
| CLERK-SKILLS-INDEX | https://clerk.com/.well-known/agent-skills/index.json |
| CLERK-EXPRESS | search the Clerk docs for "Express SDK" (`@clerk/express`) — fetch via the router skill's links |
| CLERK-WEBHOOKS | search the Clerk docs for "Webhooks overview" and "Sync data to your database with webhooks" |
| SVIX-VERIFY | https://docs.svix.com/receiving/verifying-payloads/how |
| EXPRESS-ERRORS | https://expressjs.com/en/guide/error-handling.html |

> Clerk's SDKs change. Before writing auth code, read the **installed** `@clerk/express` version's exports (`node -e "import('@clerk/express').then(m=>console.log(Object.keys(m)))"`) and the Clerk skill. Where this plan and the skill disagree on **API names**, the skill/installed package wins; where they disagree on **behavior** (error shapes, ordering, security rules), this plan wins.

---

## 1. Design decisions (fixed — do not change)

| Topic | Decision |
|---|---|
| Source of truth for identity | Clerk. Local `users` row is a mirror keyed by `clerk_user_id`. |
| Auth failures | Always our JSON error shape. **401** = no/invalid token. **403** = valid token but account inactive/deleted. Never a redirect (Clerk's default `requireAuth` redirects — do NOT use it as-is). |
| CSRF / token misuse | `authorizedParties` (the token's `azp` claim) restricted to `env.CORS_ORIGINS`. |
| Missing local user | Lazy-provision on first request (fetch email from Clerk Backend API). Webhooks may arrive late or out of order. |
| Tier source | Clerk user `public_metadata.tier` (`"free"` \| `"paid"`), default FREE. Synced by webhook. |
| Daily limits | FREE = **5 per tool per day** (env `FREE_DAILY_LIMIT`, default 5). PAID = env `PAID_DAILY_LIMIT` (default **100** — *assumption, the user may change it*). ADMIN role = unlimited. Day boundary = **UTC midnight**. |
| Quota order inside a tool route | **authenticate → validate input → target policy (Phase 4) → consume quota → run.** Invalid or blocked requests must NOT burn quota. |
| Refunds | If the server fails *before the tool actually executes* (e.g. queue down), refund the exact unit using the `usage_date` returned at consume time. A tool that ran and failed on the target's side is NOT refunded. |
| Webhooks | Raw body, signature-verified, **idempotent** via `webhook_events` (PK = svix-id), 2xx for ignored events, 5xx on processing failure so Clerk retries. |
| Test auth | Auth middleware is **injectable** into `createApp()`; tests inject a fake. No fake-auth code path exists in production code. |

---

## 2. Target changes (end of Phase 3)

```
server/src/
  config/
    env.js                 # + Clerk + limit vars
    limits.js              # tier→limit, nextResetAt()
  middleware/
    auth.js                # clerkAuth(), requireAuth()
    attachUser.js          # resolve/lazy-provision local user -> req.user
    quota.js               # enforceQuota(tool), refundQuota(req)
  services/
    clerkSync.js           # pure event handlers (created/updated/deleted)
  db/repos/
    userRepo.js            # + updateFromClerk, setTier
    usageRepo.js           # consume() now also returns usageDate; + refund()
    auditRepo.js           # NEW
    webhookRepo.js         # NEW (claim / markProcessed / markFailed)
  routes/
    user.js                # GET /api/user/me, GET /api/user/usage
    webhooks.js            # POST /api/webhooks/clerk
  utils/
    clientIp.js
docs/
  quota-contract.md        # how Phase 5/7 tool routes must use quota
tests/
  helpers/auth.js          # fake auth injection helpers
  unit/limits.test.js
  api/auth.test.js  api/user.test.js  api/quota.test.js  api/webhooks.test.js
```

---

## 3. Tasks

### Block A — Orientation, keys, packages, config

- [x] **T3.1 Orientation (read-only)**
  - Clone the skill repos from §0.1. Read `/tmp/skills-clerk/skills/core/clerk/SKILL.md` fully. From `CLERK-SKILLS-INDEX`, list the skill names and read the ones about **Express/backend setup**, **webhooks** and **syncing users to a database** (names vary; pick by description).
  - Read `server/src/app.js` (it must show the middleware order from Phase 1) and `server/src/routes/index.js`.
  - Report: the skill names you will rely on; whether the installed/latest `@clerk/express` exports a webhook helper (`verifyWebhook` from a `/webhooks` subpath) — if not, plan to use the `svix` package.
  - No commit.

- [ ] **T3.2 Clerk project keys (USER ACTION — ask, then wait)**
  - Ask the user to: create a Clerk application (development instance), then copy **Publishable key** and **Secret key** into `server/.env` as `CLERK_PUBLISHABLE_KEY` and `CLERK_SECRET_KEY`. The webhook signing secret comes later (T3.21) — leave `CLERK_WEBHOOK_SIGNING_SECRET` empty for now.
  - Do NOT print the values back. Verify only that the variables are present: `grep -c '^CLERK_SECRET_KEY=.\+' server/.env` → `1`.
  - No commit.

- [x] **T3.3 Install packages**
  - `npm i @clerk/express --workspace server`; add `svix` only if T3.1 found no webhook helper in `@clerk/express`. Dev: nothing new (svix, if installed, is also used by tests to sign payloads — then install it as a normal dependency anyway).
  - Commit: `chore(server): add clerk sdk`

- [x] **T3.4 Env vars**
  - Add to `src/config/env.js` zod schema: `CLERK_PUBLISHABLE_KEY` (starts `pk_`), `CLERK_SECRET_KEY` (starts `sk_`), `CLERK_WEBHOOK_SIGNING_SECRET` (starts `whsec_`; **optional when `NODE_ENV !== 'production'`, required in production**), `FREE_DAILY_LIMIT` (int ≥ 1, default 5), `PAID_DAILY_LIMIT` (int ≥ 1, default 100).
  - Update `server/.env.example` (placeholders like `pk_test_xxx`, never real values) and `vitest.config.js` `test.env` with dummy-but-well-formed values.
  - Update `tests/env.test.js`: wrong prefix rejected; production requires the webhook secret; limits default.
  - Commit: `feat(server): clerk and limit env vars`

- [x] **T3.5 `src/config/limits.js` (pure, no I/O)**
  - Export `limitFor({ tier, role }, env)` → number or `Infinity` (ADMIN). Export `nextResetAt(now = new Date())` → ISO string of the next UTC midnight; export `utcDate(now)` → `YYYY-MM-DD`.
  - Unit tests `tests/unit/limits.test.js`: FREE→5, PAID→100, ADMIN→Infinity; `nextResetAt('2026-11-11T23:59:59Z')` → `2026-11-12T00:00:00.000Z`; leap-day and month-end cases.
  - Commit: `feat(server): tier limits and reset time helpers`

### Block B — Authentication

- [x] **T3.6 `middleware/auth.js`**
  - **Read first:** the Clerk Express skill/docs section on `clerkMiddleware`, `getAuth`, `authorizedParties`.
  - `clerkAuth(env)` returns `clerkMiddleware({ publishableKey, secretKey, authorizedParties: env.CORS_ORIGINS })`.
  - `requireAuth(req, _res, next)`: `const { userId } = getAuth(req)`; if falsy → `next(AppError.unauthorized('Authentication required'))`; else set `req.auth = { clerkUserId: userId, sessionId }`. **Must not** redirect.
  - **Injectability:** change `createApp({ env, logger, auth })` — `auth` is `{ middleware, requireAuth }`; defaults to the real Clerk ones. Mount `auth.middleware` on `/api` AFTER the rate limiter and BEFORE `routes`.
  - Commit: `feat(server): clerk auth middleware with injectable provider`

- [x] **T3.7 `middleware/attachUser.js`**
  - After `requireAuth`: `userRepo.findByClerkId(req.auth.clerkUserId)`.
  - If missing → **lazy provision**: fetch the Clerk user via the Backend API client (`clerkClient.users.getUser`) → primary email + `public_metadata.tier` → `userRepo.upsertFromClerk(...)` (idempotent; webhook may race us). Wrap Clerk API failure → `AppError(502, 'UPSTREAM_AUTH_ERROR', ...)`.
  - If `user.isActive === false` or `user.deletedAt` → `AppError.forbidden('Account disabled')` (code `ACCOUNT_DISABLED`).
  - Set `req.user = { id, clerkUserId, tier, role }` (plain object, nothing else).
  - Commit: `feat(server): attachUser with lazy provisioning`

- [x] **T3.8 Audit + client IP utilities**
  - `utils/clientIp.js`: return `req.ip` (Express already honours `trust proxy` from Phase 1). Never read `X-Forwarded-For` manually.
  - `db/repos/auditRepo.js`: `log({ actorId, action, entityType, entityId, ip, userAgent, metadata })` → inserts into `audit_logs`. **Never throws**: catch, `logger.error`, continue (audit must not break requests). Truncate `userAgent` to 300 chars. Never put tokens/emails in `metadata`.
  - Commit: `feat(server): audit log repository`

- [x] **T3.9 Repository changes**
  - `usageRepo.consume`: update the SQL to `RETURNING used, usage_date`; return `{ allowed, used, usageDate }` (usageDate as `YYYY-MM-DD` string). Update Phase 2 tests accordingly (`tests/db/usage.test.js`).
  - `usageRepo.refund({ userId, tool, usageDate })`: `UPDATE usage_counters SET used = GREATEST(used - 1, 0), updated_at = now() WHERE user_id = $1 AND tool = $2::"ToolName" AND usage_date = $3::date` (tagged template, bound params). Returns boolean (row existed).
  - `userRepo`: `updateFromClerk({ clerkUserId, email, tier })`, `setTier(clerkUserId, tier)`; email always lower-cased.
  - Add DB tests: refund decrements by exactly 1 on the **right day**; refund never goes below 0; a refund with yesterday's date doesn't touch today's row.
  - Verify: `npm run test:db --workspace server 2>&1 | tail -n 15` green.
  - Commit: `feat(db): usage refund and consume returns usage date`

- [x] **T3.10 `routes/user.js`**
  - Mount at `/api/user` with `requireAuth` → `attachUser`.
  - `GET /api/user/me` → `{ id, email, tier, role, createdAt }` (no `clerkUserId`, no internals).
  - `GET /api/user/usage` → `{ date, resetsAt, tiers: { tier }, tools: [{ tool, used, limit, remaining }] }` — list **every** `ToolName` enum value, `used` = 0 when no row; `limit`/`remaining` = `null` for unlimited (ADMIN).
  - Responses must send `Cache-Control: no-store`.
  - Commit: `feat(server): user profile and usage endpoints`

### Block C — Quota enforcement

- [x] **T3.11 `middleware/quota.js`**
  - `enforceQuota(tool)` returns middleware (requires `req.user`; if absent → programmer error 500):
    1. `limit = limitFor(req.user, env)`; ADMIN → set `req.quota = { tool, limit: null, consumed: false }`, call `next()`.
    2. `const r = await usageRepo.consume({ userId, tool, limit })`.
    3. Always set headers: `X-Quota-Limit`, `X-Quota-Remaining`, `X-Quota-Reset` (ISO from `nextResetAt`).
    4. `!r.allowed` → `AppError(429, 'QUOTA_EXCEEDED', 'Daily limit reached for <tool>', { limit, resetsAt })` plus `Retry-After` (seconds to reset).
    5. Allowed → `req.quota = { tool, limit, used: r.used, usageDate: r.usageDate, consumed: true }`.
  - `refundQuota(req)`: if `req.quota?.consumed` and not already refunded → `usageRepo.refund(...)`, mark `req.quota.refunded = true`. Idempotent. Never throws (log on failure).
  - Commit: `feat(server): quota enforcement middleware`

- [x] **T3.12 `docs/quota-contract.md` (≤ 40 lines)**
  - Document, for the authors of Phase 5/7 tool routes: the order **auth → zod-validate → target policy → `enforceQuota(tool)` → execute**; when to call `refundQuota(req)` (server-side failure before execution); that quota headers are always sent; example route skeleton (10 lines).
  - Commit: `docs: quota contract for tool routes`

### Block D — Webhooks

- [x] **T3.13 Raw-body mounting in `app.js`**
  - Signature verification needs the **exact raw bytes**. Mount the webhook router **before** `express.json()`:
    `app.use('/api/webhooks', express.raw({ type: 'application/json', limit: '1mb' }), webhookRouter)`.
  - It must also bypass `auth.middleware` and the per-IP global limiter's *auth requirement* (keep the global rate limiter but with a higher ceiling for this path, e.g. a separate limiter 300/min). Webhooks authenticate by signature, not by session.
  - Add a test proving `express.json` is NOT applied to `/api/webhooks/*` (`req.body` is a `Buffer`).
  - Commit: `feat(server): raw body mount for webhooks`

- [x] **T3.14 `webhookRepo` + `services/clerkSync.js`**
  - `webhookRepo.claim({ id, source, eventType })` → `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING id`; returns `true` if newly claimed. If it conflicts, check `processed_at`: if already processed → duplicate (skip); if NOT processed (previous attempt failed) → allow re-processing. `markProcessed(id)`, `markFailed(id, message<=1000 chars)`.
  - `clerkSync.js` — pure functions taking the event payload + repos:
    - `user.created` / `user.updated`: primary email = the `email_addresses` entry whose `id === primary_email_address_id`; tier from `public_metadata.tier` (`"paid"` → PAID, anything else → FREE); call `upsertFromClerk` / `updateFromClerk`. **Out-of-order safe**: `user.updated` for an unknown user upserts.
    - `user.deleted`: `userRepo.softDelete` (email → NULL), audit `user.deleted`.
    - Any other type: ignore (return `{ handled:false }`).
    - Audit `user.created` and `tier.changed` (when tier actually changed).
  - Commit: `feat(server): webhook idempotency repo and clerk sync handlers`

- [x] **T3.15 `routes/webhooks.js` — `POST /api/webhooks/clerk`**
  - Verify signature with Clerk's helper (or `svix` `Webhook.verify(rawBody, { 'svix-id', 'svix-timestamp', 'svix-signature' })`) using `CLERK_WEBHOOK_SIGNING_SECRET`. Svix rejects timestamps outside a 5-minute tolerance — keep that default.
  - Missing secret (dev only) → `AppError(503, 'WEBHOOKS_NOT_CONFIGURED')`. Bad/missing signature → `400 INVALID_SIGNATURE`. **Never** echo the payload or secret in errors/logs.
  - Flow: verify → `claim` → (duplicate? `200 { received:true, duplicate:true }`) → run handler → `markProcessed` → `200`. Handler throws → `markFailed` → **`500`** so Clerk retries.
  - Log only `{ svixId, type, outcome }`.
  - Commit: `feat(server): clerk webhook endpoint`

### Block E — Tests (all with the real test DB from Phase 2; no live Clerk calls)

- [x] **T3.16 Test helpers `tests/helpers/auth.js`**
  - `makeTestAuth()` → an `auth` object for `createApp({ auth })`: middleware reads header `x-test-clerk-id` (and `x-test-session`), `requireAuth` 401s when absent. This file lives under `tests/` only and must not be imported from `src/`.
  - `asUser(app, { clerkId, tier, role })` helper that seeds a user in the DB and returns a supertest agent with the header set.
  - A stub for the Clerk Backend client used by lazy-provisioning (injected via `createApp` options or module mock) so tests never hit the network.
  - Commit: `test(server): auth test helpers`

- [x] **T3.17 `tests/api/auth.test.js` and `user.test.js`**
  - No token → **401** with our JSON shape (and no redirect / `Location` header).
  - Valid user → `/api/user/me` 200, response has no `clerkUserId`.
  - Unknown Clerk id → lazy-provisioned (row created) → 200; calling twice creates one row.
  - Deactivated user → **403 ACCOUNT_DISABLED**; soft-deleted user → 403.
  - `/api/user/usage` lists all tools with `used:0` initially, `limit:5` for FREE, `limit:null` for ADMIN; header `Cache-Control: no-store`.
  - Commit: `test(server): auth and user endpoints`

- [x] **T3.18 `tests/api/quota.test.js`**
  - Register a throwaway test-only route in the test file (`app.post('/__t/dns', requireAuth, attachUser, enforceQuota('DNS'), handler)`) — **do not add such a route to `src/`**.
  - FREE user: requests 1–5 → 200 with `X-Quota-Remaining` 4,3,2,1,0; request 6 → **429 `QUOTA_EXCEEDED`** with `Retry-After` and `X-Quota-Reset`.
  - **20 parallel HTTP requests** → exactly 5×200 and 15×429; DB `used === 5`.
  - Different tool (`WHOIS`) is a separate counter; PAID user allowed beyond 5; ADMIN never gets 429 and no `usage_counters` row is written.
  - Refund: handler calls `refundQuota(req)` → `used` back to 0; calling it twice refunds once.
  - A request that fails zod validation **before** the quota middleware leaves `used` unchanged.
  - Commit: `test(server): quota enforcement over HTTP`

- [x] **T3.19 `tests/api/webhooks.test.js`**
  - Sign payloads in the test with the `svix` library using a test secret (`whsec_…` base64), same method Clerk uses.
  - Valid `user.created` → 200, user row exists, `webhook_events.processed_at` set, audit row `user.created`.
  - **Replay** same `svix-id` → 200 `duplicate:true`, still one user, still one event row.
  - Tampered body → 400 `INVALID_SIGNATURE`; missing headers → 400; timestamp 10 min old → 400.
  - `user.updated` for unknown user → upserted (out-of-order). `public_metadata.tier:"paid"` → tier PAID; later `"free"` → FREE + `tier.changed` audit.
  - `user.deleted` → soft-deleted, email NULL; same email can register again.
  - Handler failure (force the repo to throw) → **500**, `processed_at` NULL, `error` stored; a retry with the same `svix-id` succeeds and processes once.
  - Unknown event type → 200 `handled:false`, no state change.
  - Commit: `test(server): clerk webhooks`

### Block F — Hardening and close-out

- [x] **T3.20 Security review (checklist task — report findings, fix any)**
  - `grep -rn "CLERK_SECRET\|whsec_\|sk_test\|sk_live" server --include=*.js -l | grep -v node_modules` → only `env.js` and tests (with dummy values). No secret in logs: confirm pino `redact` still covers `authorization` and add `req.headers["svix-signature"]`.
  - Confirm no route reads `req.body` of `/api/webhooks` as parsed JSON before verification.
  - Confirm `/api/user/*` and all future tool routes sit behind `requireAuth` (list every route with `app._router.stack` or a quick script; the only public routes must be `/api/health`, `/api/ready`, `/api/webhooks/*`).
  - Confirm CORS still lists only `CORS_ORIGINS` and `credentials:true` is paired with an explicit origin allowlist (never `*`).
  - Confirm error responses for 401/403/429 contain no stack, token or Clerk internals.
  - Commit only if fixes were needed: `fix(server): security review fixes`

- [ ] **T3.21 Optional live checks (USER-ASSISTED — skip if the user has no tunnel)**
  - Webhook: user exposes `localhost:3001` through a tunnel (e.g. `ngrok http 3001`), adds endpoint `https://<tunnel>/api/webhooks/clerk` in Clerk Dashboard → Webhooks, subscribes to `user.created`, `user.updated`, `user.deleted`, pastes the signing secret into `server/.env` as `CLERK_WEBHOOK_SIGNING_SECRET` (do not echo it), and sends a test event.
  - Confirm: server logs `{ svixId, type, outcome:'processed' }`; row appears in `webhook_events`. Resending the same event shows `duplicate`.
  - JWT checks against the real Clerk instance are deferred to the client phase (the React app obtains real session tokens). Record this in your report.
  - No commit.

- [x] **T3.22 Final verification**
  - `npm test --workspace server` and `npm run test:db --workspace server` and the API tests all green (report counts).
  - `curl -si localhost:3001/api/user/me` → 401 JSON (no redirect); `/api/health`, `/api/ready` unchanged.
  - `git log --oneline | head -n 25`; print `tree server/src -L 2`.

---

## 4. Definition of Done (Phase 3)

- [ ] 22 tasks ticked, one commit each; secrets never committed or logged.
- [x] Unauthenticated → 401 JSON; disabled → 403; never a redirect.
- [x] 20 parallel requests with a limit of 5 → exactly 5 succeed (proved over HTTP and in SQL).
- [x] Invalid input and (later) blocked targets cannot burn quota; refunds hit the correct UTC day and never go below 0.
- [x] Webhooks: signature-verified, replay-safe, out-of-order-safe, retried on failure, soft-delete frees the email.
- [x] Every non-public route is behind `requireAuth`; the only public routes are health, ready, webhooks.
- [x] `docs/quota-contract.md` exists for Phases 5 and 7.
- [x] Zero Python; `client/` untouched.

**When finished, report:** `@clerk/express` version, whether Clerk's webhook helper or `svix` was used, test counts, and the limits you assumed (FREE 5 / PAID 100 / ADMIN unlimited). Then wait for the Phase 4 file (target-validation policy, SSRF-safe DNS resolution, per-user rate limiting, Redis client, metrics).
