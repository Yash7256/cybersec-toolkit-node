# Database operations

PostgreSQL 17 + Prisma 7. Schema and index rationale live in
`IMPLEMENTATION/DATABASE-DESIGN.md` — copy from it, never improvise the schema.

## Start the local database

```bash
docker compose up -d db          # dev + test + bench databases on first boot
docker compose ps                # wait for healthy
```

Connection strings (offsets may differ — host 5432 is used by the system PG):

```
DATABASE_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec        # runtime (pooled in prod)
DIRECT_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec          # migrations
TEST_DATABASE_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec_test
```

Keep them in `server/.env` only (gitignored). Never commit real credentials.

## Why `DIRECT_URL` is separate from `DATABASE_URL`

The app connects through a pooled string (Supabase pooler, transaction mode).
DDL and advisory locks do not survive transaction pooling, so the **Prisma CLI
always uses `DIRECT_URL`** (`prisma.config.ts`). Locally both point at the same
database.

## Migrations

```bash
# In development: edit prisma/schema.prisma, then
npm run db:migrate --workspace server -- --name add_something

# Apply committed migrations (CI, staging, production)
npm run db:deploy --workspace server

npm run db:generate --workspace server   # regenerate the client
npm run db:seed     --workspace server   # idempotent dev seed
npm run db:studio   --workspace server   # browse data
```

**Production only ever runs `migrate deploy`.** Never `migrate dev`, `db push`
or `migrate reset` against production. `db:reset` refuses to run when
`NODE_ENV=production`.

## Tests

```bash
npm test     --workspace server   # unit, no database
npm run test:db --workspace server  # integration; needs TEST_DATABASE_URL ending in _test
```

The DB project runs files serially because they share one database and call
`TRUNCATE ... CASCADE` between tests.

## Performance

`docs/db-benchmark.md` records the 1M-run / 3M-finding `EXPLAIN (ANALYZE)`
results. Regenerate with `node server/scripts/bench-seed.js --all` against a
`_bench` database. Any new hot query should be added there before shipping.
