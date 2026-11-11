import { prisma } from '../client.js'
import { utcDate } from '../../config/limits.js'

// Atomic quota consumption (DATABASE-DESIGN.md §3): one statement, row-locked by
// Postgres on conflict. 1 row returned => allowed (new count); 0 rows => limit
// reached and nothing was written.
export async function consume({ userId, tool, limit }) {
  const rows = await prisma.$queryRaw`
    INSERT INTO usage_counters (user_id, tool, usage_date, used)
    VALUES (${userId}::uuid, ${tool}::"ToolName", (now() AT TIME ZONE 'UTC')::date, 1)
    ON CONFLICT (user_id, tool, usage_date)
    DO UPDATE SET used = usage_counters.used + 1, updated_at = now()
    WHERE usage_counters.used < ${limit}
    RETURNING used, to_char(usage_date, 'YYYY-MM-DD') AS usage_date
  `

  if (rows.length > 0) {
    return {
      allowed: true,
      used: Number(rows[0].used),
      usageDate: rows[0].usage_date,
    }
  }

  const current = await prisma.$queryRaw`
    SELECT used, to_char(usage_date, 'YYYY-MM-DD') AS usage_date
    FROM usage_counters
    WHERE user_id = ${userId}::uuid
      AND tool = ${tool}::"ToolName"
      AND usage_date = (now() AT TIME ZONE 'UTC')::date
  `

  if (current.length === 0) {
    return { allowed: false, used: 0, usageDate: utcDate() }
  }
  return {
    allowed: false,
    used: Number(current[0].used),
    usageDate: current[0].usage_date,
  }
}

// Refund exactly one unit on the day it was consumed. Never below zero.
export async function refund({ userId, tool, usageDate }) {
  const rows = await prisma.$queryRaw`
    UPDATE usage_counters
    SET used = GREATEST(used - 1, 0), updated_at = now()
    WHERE user_id = ${userId}::uuid
      AND tool = ${tool}::"ToolName"
      AND usage_date = ${usageDate}::date
    RETURNING used
  `
  return rows.length > 0
}

export async function getToday({ userId }) {
  const rows = await prisma.$queryRaw`
    SELECT tool, used FROM usage_counters
    WHERE user_id = ${userId}::uuid
      AND usage_date = (now() AT TIME ZONE 'UTC')::date
  `
  return rows.map((row) => ({ tool: row.tool, used: Number(row.used) }))
}
