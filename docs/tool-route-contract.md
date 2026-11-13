# Tool route contract

Every tool route uses this order:

`requireAuth → attachUser → submit limiters → zod → assertNotCoolingDown → validateTarget(s) → targetLimiter → enforceQuota → execute`

Submit limiters run before validation to cap cheap abuse. Validation, cooldowns,
and rate limits never consume daily quota.

Tool authors must:

- Connect only with the validated `addresses` and `pinnedLookup(addresses)`.
- Never call DNS or `fetch()` on user-controlled input.
- Follow redirects manually through `validateRedirect`; allow at most five hops.
- Return generic errors only; never expose resolved IPs, CIDRs, stack traces, or internal errors.
- Call `refundQuota(req)` only when execution has not started and quota was consumed.
- Record policy blocks in the policy metric and audit log.

To add a tool: create its zod schema, definition, normalizer, executor,
summary, and fixtures; export it from `tools/index.js`; mount it through the
shared route factory; then add one row to the contract test.

Async tools return `202` with `Location` and `pollUrl`; clients may submit an
`Idempotency-Key` and receive the same run on replay. Workers revalidate target
policy immediately before execution and use fresh pinned addresses.

Example:

```js
router.post('/scan', requireAuth, attachUser, ...submitLimiters,
  validateBody(schema), assertNotCoolingDown, asyncHandler(async (req, res) => {
    const [target] = await validateTargets(req.body.targets, { env })
    await targetLimiter(req.user.id, target.targetKey)
    await enforceQuota('PORT_SCAN')(req, res, async () => {
      const result = await execute(target.addresses, { lookup: pinnedLookup(target.addresses) })
      res.json(result)
    })
  }))
```
