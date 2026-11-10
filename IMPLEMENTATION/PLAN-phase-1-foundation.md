# PHASE 1 — Server Foundation (Express, ES Modules, JavaScript)

> **For OpenCode.** Read this file top to bottom ONCE, then work on exactly ONE task at a time.
> Project: npm-workspaces monorepo `CyberSec-Toolkit` → `client/` (React 19 + Vite) and `server/` (Express, ESM, `node --watch`, port 3001).
> **Never touch `client/`. Never write Python.**

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** (e.g. `T1.5`), tick its checkbox `[x]` in THIS file, commit, then **stop and report** in ≤ 10 lines. Wait for "next".
2. Do NOT read the whole repo. Read only the files a task names. Use `sed -n 'START,ENDp'` or `head -n 60` for big files.
3. Do NOT paste big command output. Pipe through `tail -n 20`. Run tests with `--reporter=dot`.
4. Fetch a skill/rule file ONLY when the task says so, and read only the named rule file, not the whole skill folder.
5. One commit per task, message format given in each task. No unrelated refactors.
6. If a task's verification fails twice, stop and report the exact error. Do not improvise a different design.

### 0.1 Skill / reference registry (all verified to exist)

Clone once into `/tmp` (skip if already there), then read single files:

```bash
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina
# Node.js best-practice skill  -> /tmp/skills-mcollina/skills/node/SKILL.md
# Rule files                   -> /tmp/skills-mcollina/skills/node/rules/<name>.md
#   error-handling.md  async-patterns.md  modules.md  testing.md  logging.md
#   environment.md  graceful-shutdown.md  performance.md  flaky-tests.md
```

Official docs (fetch only the page named by the task):

| Short name | URL |
|---|---|
| EXPRESS-SECURITY | https://expressjs.com/en/advanced/best-practice-security.html |
| EXPRESS-PERF | https://expressjs.com/en/advanced/best-practice-performance.html |
| EXPRESS-ERRORS | https://expressjs.com/en/guide/error-handling.html |
| HELMET | https://helmetjs.github.io/ |
| RATE-LIMIT | https://github.com/express-rate-limit/express-rate-limit |
| PINO | https://getpino.io |
| PINO-HTTP | https://github.com/pinojs/pino-http |
| ZOD | https://zod.dev |
| VITEST | https://vitest.dev/guide/ |
| SUPERTEST | https://github.com/ladjs/supertest |

---

## 1. Target structure (end of Phase 1)

```
server/
  .env.example
  package.json
  vitest.config.js
  src/
    config/
      env.js              # parseEnv(raw) [pure, throws] + exported frozen `env`
    utils/
      AppError.js
      asyncHandler.js     # only if Express < 5
      logger.js           # pino instance factory
    middleware/
      requestId.js
      notFound.js
      errorHandler.js
    routes/
      index.js            # mounts all routers under /api
      health.js           # GET /api/health  and  GET /api/ready
    app.js                # createApp({ env, logger }) -> express app (no listen)
    server.js             # listen + graceful shutdown
  tests/
    env.test.js
    health.test.js
    errors.test.js
    security.test.js
```

---

## 2. Tasks

### Block A — Inspect & install

- [x] **T1.1 Inspect current server (read-only)**
  - Run: `cat package.json server/package.json && ls -R server/src && node -v && npm ls express --workspace server --depth=0`
  - Record in your report: workspace name of server, Express major version (4 or 5), Node version.
  - **Decision rule:** if Express is **4** → you MUST create `utils/asyncHandler.js` in T1.7 and wrap all async handlers. If **5** → async errors propagate natively, skip asyncHandler.
  - Node must be ≥ 20. If lower, stop and tell the user.
  - No commit.

- [x] **T1.2 Install dependencies**
  - Run (from repo root, use the workspace name from T1.1; examples assume `server`):
    ```bash
    npm i cors helmet dotenv zod pino pino-http express-rate-limit --workspace server
    npm i -D vitest supertest pino-pretty --workspace server
    ```
  - Verify: `npm ls --workspace server --depth=0 | tail -n 20` shows all of them.
  - Commit: `chore(server): add core dependencies`

### Block B — Config

- [ ] **T1.3 `src/config/env.js`**
  - **Fetch & read:** `/tmp/skills-mcollina/skills/node/rules/environment.md` and the ZOD docs "Basic usage / coerce / transform".
  - Export `parseEnv(raw = process.env)` — **pure function**, returns a frozen object, throws `Error` with a readable multi-line message on invalid input. It must NOT call `process.exit`.
  - Schema (zod):
    | Var | Rule | Default |
    |---|---|---|
    | `NODE_ENV` | enum development / test / production | development |
    | `PORT` | coerce int 1–65535 | 3001 |
    | `LOG_LEVEL` | enum fatal/error/warn/info/debug/trace/silent | info |
    | `CORS_ORIGINS` | comma string → trimmed non-empty `string[]`, each must be a valid URL origin | `http://localhost:5173` |
    | `TRUST_PROXY` | coerce int ≥ 0 | 0 |
    | `RATE_LIMIT_WINDOW_MS` | coerce int ≥ 1000 | 60000 |
    | `RATE_LIMIT_MAX` | coerce int ≥ 1 | 100 |
    | `BODY_LIMIT` | string | `100kb` |
  - In the same file: `import 'dotenv/config'` at top, then `export const env = (() => { try { return parseEnv() } catch (e) { console.error(e.message); process.exit(1) } })()`.
    - Keep `NODE_ENV=test` from skipping the exit: when `NODE_ENV === 'test'` throw instead of exit.
  - Verify: `node -e "import('./server/src/config/env.js').then(m=>console.log(m.env))"` prints the object. Then run with `PORT=abc` → prints a readable error and exits 1.
  - Commit: `feat(server): validated env config`

- [ ] **T1.4 `.env.example` and `.gitignore`**
  - Create `server/.env.example` listing EVERY var from T1.3 with a one-line `#` comment each.
  - Create `server/.env` as a copy (user's local file).
  - Ensure repo-root `.gitignore` contains `.env`, `.env.*`, `!.env.example`, `node_modules`, `coverage`, `dist`.
  - Verify: `git check-ignore server/.env` prints the path; `git status --short` does NOT list `server/.env`.
  - Commit: `chore(server): env example and gitignore`

### Block C — Utilities

- [ ] **T1.5 `src/utils/AppError.js`**
  - `class AppError extends Error` with `(statusCode, code, message, details?)`; set `this.name='AppError'`, `this.isOperational = true`; `Error.captureStackTrace`.
  - Static helpers: `AppError.badRequest(msg, details)`, `.unauthorized()`, `.forbidden()`, `.notFound()`, `.tooMany()`, each with a stable machine `code` (`BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `RATE_LIMITED`).
  - **Read first:** `/tmp/skills-mcollina/skills/node/rules/error-handling.md` (operational vs programmer errors).
  - Commit: `feat(server): AppError`

- [ ] **T1.6 `src/utils/logger.js`**
  - **Read first:** `/tmp/skills-mcollina/skills/node/rules/logging.md` + PINO docs "redaction".
  - Export `createLogger(env)`: pino with `level: env.LOG_LEVEL`; in development only use the `pino-pretty` transport; in production plain JSON.
  - **Redact** (censor `[redacted]`): `req.headers.authorization`, `req.headers.cookie`, `res.headers["set-cookie"]`, `*.password`, `*.token`, `*.secret`.
  - Commit: `feat(server): pino logger with redaction`

### Block D — Middleware & routes

- [ ] **T1.7 `middleware/requestId.js` + (Express 4 only) `utils/asyncHandler.js`**
  - requestId: reuse inbound `x-request-id` only if it matches `/^[A-Za-z0-9._-]{8,64}$/`, else `crypto.randomUUID()`. Set `req.id` and response header `x-request-id`.
  - Commit: `feat(server): request id middleware`

- [ ] **T1.8 `middleware/notFound.js` and `middleware/errorHandler.js`**
  - **Read first:** EXPRESS-ERRORS page.
  - notFound → `next(AppError.notFound('Route not found'))`.
  - errorHandler (4-arg signature):
    - `AppError` → its status/code/message/details.
    - zod `ZodError` → 400, code `VALIDATION_ERROR`, details = flattened issues.
    - body-parser errors (`type === 'entity.parse.failed'` → 400 `INVALID_JSON`; `entity.too.large` → 413 `PAYLOAD_TOO_LARGE`).
    - anything else → 500 `INTERNAL_ERROR`, message `"Internal server error"` in production, real message in development.
    - Response shape ALWAYS: `{ "error": { "code": "...", "message": "...", "requestId": "...", "details"?: ... } }`. Never send a stack trace in production.
    - Log 5xx with `logger.error({ err, reqId })`, 4xx with `logger.warn`.
    - If `res.headersSent` → delegate with `next(err)`.
  - Commit: `feat(server): not-found and central error handler`

- [ ] **T1.9 `routes/health.js` and `routes/index.js`**
  - `GET /api/health` → `200 { status:"ok", uptime: process.uptime(), timestamp: new Date().toISOString() }` (liveness: no dependencies checked).
  - `GET /api/ready` → `200 { status:"ready", checks:{} }` — a stub; Phase 2 will add the DB check here. Keep a `checks` registry array so Phase 2 only pushes one function.
  - `routes/index.js` exports a Router mounting `health` at `/`.
  - Commit: `feat(server): health and readiness routes`

- [ ] **T1.10 `src/app.js` — `createApp({ env, logger })`**
  - **Read first:** EXPRESS-SECURITY, HELMET, RATE-LIMIT (README "Usage" + "Configuration"), PINO-HTTP README.
  - Must NOT call `listen`. Defaults: `env` from config, `logger` from `createLogger`.
  - `app.disable('x-powered-by')`; `app.set('trust proxy', env.TRUST_PROXY)`.
  - **Exact middleware order:**
    1. requestId
    2. pino-http (`logger`, `genReqId: req => req.id`, `autoLogging: { ignore: req => req.url === '/api/health' }`)
    3. helmet()
    4. cors: allowlist from `env.CORS_ORIGINS`, `credentials: true`, methods GET/POST/PUT/PATCH/DELETE/OPTIONS, `maxAge: 600`. Non-listed origins get NO CORS headers (not an error).
    5. `express.json({ limit: env.BODY_LIMIT })`
    6. global rate limiter on `/api` (`windowMs`, `limit` from env, `standardHeaders: 'draft-8'`, `legacyHeaders: false`, handler → `AppError.tooMany`)
    7. `app.use('/api', routes)`
    8. notFound
    9. errorHandler
  - Commit: `feat(server): createApp with security middleware stack`

- [ ] **T1.11 `src/server.js` — listen and graceful shutdown**
  - **Read first:** `/tmp/skills-mcollina/skills/node/rules/graceful-shutdown.md`.
  - `createApp()` → `http.createServer(app)` → listen on `env.PORT`; log the URL.
  - On `SIGINT`/`SIGTERM`: log, `server.close()`, call a `shutdownHooks` array (empty now; Phase 2 adds Prisma disconnect), force `process.exit(1)` after 10 s if not closed. Guard against double-signal.
  - `process.on('unhandledRejection')` and `'uncaughtException'` → log fatal, run shutdown, exit 1.
  - Set `server.keepAliveTimeout = 65_000` and `server.headersTimeout = 66_000`.
  - Commit: `feat(server): server entry with graceful shutdown`

### Block E — Wire-up & cleanup

- [ ] **T1.12 package.json scripts and removal of the old demo**
  - `server/package.json`: `"type":"module"`, scripts `"dev":"node --watch src/server.js"`, `"start":"node src/server.js"`, `"test":"vitest run"`, `"test:watch":"vitest"`.
  - Delete `server/src/index.js` (the old `/api/hello` demo). Check `client/` for any call to `/api/hello` using `grep -rn "api/hello" client/src | head` — if found, report it, do NOT edit client.
  - Root `package.json` scripts `dev`, `dev:server`, `dev:client` must still work (don't change client scripts).
  - Verify: `npm run dev:server` boots and logs the URL; `curl -s localhost:3001/api/health`.
  - Commit: `refactor(server): replace demo entry with structured app`

### Block F — Tests

- [ ] **T1.13 Vitest config**
  - **Read first:** `/tmp/skills-mcollina/skills/node/rules/testing.md` (skim) and VITEST "Configuring".
  - `server/vitest.config.js`: `environment:'node'`, `include:['tests/**/*.test.js']`, set `NODE_ENV=test` and `LOG_LEVEL=silent` via `test.env`.
  - Commit: `test(server): vitest config`

- [ ] **T1.14 Write the 4 test files** (use `supertest` against `createApp()`; never call `listen`)
  - `tests/env.test.js` — defaults applied; `PORT=abc` throws; `CORS_ORIGINS="a, ,b"` → trimmed array; invalid URL in CORS rejected; result is frozen.
  - `tests/health.test.js` — `/api/health` 200 + shape; `/api/ready` 200; `x-powered-by` header absent; `x-request-id` present and reused when valid inbound, replaced when invalid.
  - `tests/errors.test.js` — unknown route → 404 `{error:{code:'NOT_FOUND',...}}`; malformed JSON → 400 `INVALID_JSON`; body over limit → 413; a route that throws → 500 with no stack in the body when `NODE_ENV=production`.
  - `tests/security.test.js` — helmet headers present (`x-content-type-options`); CORS: allowed origin echoed back, disallowed origin gets no `access-control-allow-origin`; rate limit: with `RATE_LIMIT_MAX=3` the 4th request → 429 `RATE_LIMITED`.
  - Verify: `npm test --workspace server -- --reporter=dot 2>&1 | tail -n 25` → all green.
  - Commit: `test(server): foundation test suite`

### Block G — Final verification

- [ ] **T1.15 End-to-end checks**
  - `npm run dev` from repo root → client on 5173 and server on 3001 both start.
  - `curl -s localhost:3001/api/health`, `curl -si localhost:3001/nope | head -n 12`, `curl -si -H 'Origin: http://evil.test' localhost:3001/api/health | grep -i access-control || echo "no CORS header (good)"`.
  - Browser path: `curl -s localhost:5173/api/health` returns the same JSON (Vite proxy intact).
  - Break the env on purpose (`PORT=abc npm run start --workspace server`) → readable error, exit code 1.
  - Send SIGTERM (`kill -TERM <pid>`) → log shows graceful shutdown.
  - Print `git log --oneline | head -n 16` and the final `tree server -I node_modules`.

---

## 3. Definition of Done (Phase 1)

- [ ] Every task above ticked, one commit each.
- [ ] `npm test --workspace server` green.
- [ ] Server refuses to start on invalid env.
- [ ] No stack traces in production errors; every error has the `{ error: { code, message, requestId } }` shape.
- [ ] Secrets never logged (authorization header redacted).
- [ ] `client/` untouched; zero Python files.

**When finished, report:** the Express major version used, test count, and anything you could not do. Then wait for the Phase 2 file.
