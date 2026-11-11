export function limitFor({ tier, role }, env) {
  if (role === 'ADMIN') return Infinity
  return tier === 'PAID' ? env.PAID_DAILY_LIMIT : env.FREE_DAILY_LIMIT
}

export function nextResetAt(now = new Date()) {
  const next = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0)
  )
  return next.toISOString()
}

export function utcDate(now = new Date()) {
  return now.toISOString().slice(0, 10)
}
