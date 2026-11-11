# Quota Contract for Tool Routes

Every tool route in Phases 5 and 7 must enforce quota in this exact order:

```
requireAuth -> attachUser -> zod-validate body/params -> target policy -> enforceQuota(tool) -> execute
```

Invalid input or a blocked target must never reach `enforceQuota`, because that is
the only step that consumes a unit. Quota headers are sent by `enforceQuota`.

## Route skeleton

```js
router.post(
  '/dns',
  auth.requireAuth,
  attachUser,
  validate(dnsSchema),        // unknown/invalid body -> 400, no quota burned
  targetPolicy(),             // Phase 4 SSRF/target checks, no quota burned
  enforceQuota('DNS'),
  asyncHandler(async (req, res) => {
    try {
      const result = await runDns(req.body)
      res.json(result)
    } catch (err) {
      // Only refund when the failure happened BEFORE the tool executed.
      await refundQuota(req)
      throw err
    }
  })
)
```

## Rules

- **Consume** happens inside `enforceQuota(tool)`; never call the repo directly.
- **Headers:** `enforceQuota` always sets `X-Quota-Limit`, `X-Quota-Remaining`,
  `X-Quota-Reset` (ISO string of the next UTC midnight). On `429 QUOTA_EXCEEDED`
  it also sets `Retry-After` (seconds).
- **ADMIN** is unlimited: no `usage_counters` row is written and limits are `null`.
- **Refund** (`refundQuota(req)`) only for server-side failures *before execution*
  (queue down, adapter unavailable). A tool that ran and failed on the target is
  NOT refunded.
- Refunds use the `usageDate` returned by consume, so a request spanning UTC
  midnight still debits the right day and never drops below zero.
- The day boundary is **UTC midnight**; limits are FREE 5 and PAID 100 per tool
  per day by default (`FREE_DAILY_LIMIT`, `PAID_DAILY_LIMIT`).
