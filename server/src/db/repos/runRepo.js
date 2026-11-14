import { prisma } from '../client.js'
import { randomUUID } from 'node:crypto'

const terminal = new Set(['COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED'])

export async function createQueuedWithCap({ userId, tool, target, targetKey, options = {}, quotaDate = null, cap }) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${userId}::text, 0))`
    const rows = await tx.$queryRaw`SELECT count(*)::int AS n FROM tool_runs WHERE user_id = ${userId}::uuid AND status IN ('QUEUED','RUNNING')`
    if (Number(rows[0]?.n ?? 0) >= cap) return null
    const runId = randomUUID()
    const result = await tx.$queryRaw`
      INSERT INTO tool_runs (id, user_id, tool, target, target_key, status, options, quota_date)
      VALUES (${runId}::uuid, ${userId}::uuid, ${tool}::"ToolName", ${String(target).slice(0, 255)}, ${targetKey}, 'QUEUED'::"RunStatus", ${JSON.stringify(options)}::jsonb, ${quotaDate}::date)
      RETURNING id, attempt
    `
    return result[0] ?? null
  })
}

export async function claim({ runId, workerId }) {
  const rows = await prisma.$queryRaw`UPDATE tool_runs SET status='RUNNING', worker_id=${workerId}, attempt=attempt+1, started_at=COALESCE(started_at, now()), heartbeat_at=now() WHERE id=${runId}::uuid AND status='QUEUED' RETURNING id, user_id, tool, target, target_key, options, attempt, quota_date`
  return rows[0] ?? null
}

export async function heartbeat({ runId, workerId, attempt, progressPct = 0 }) {
  const rows = await prisma.$queryRaw`UPDATE tool_runs SET heartbeat_at=now(), progress_pct=GREATEST(progress_pct, ${progressPct}) WHERE id=${runId}::uuid AND status='RUNNING' AND worker_id=${workerId} AND attempt=${attempt} RETURNING cancel_requested_at IS NOT NULL AS cancel_requested`
  return rows[0] ?? null
}

export async function completeFenced({ runId, workerId, attempt, data, summary = {}, extra = null }) {
  return prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw`UPDATE tool_runs SET status='COMPLETED', progress_pct=100, summary=${JSON.stringify(summary)}::jsonb, finished_at=now() WHERE id=${runId}::uuid AND status='RUNNING' AND worker_id=${workerId} AND attempt=${attempt} RETURNING id`
    if (!rows.length) return false
    if (extra) await extra({ tx })
    await tx.$queryRaw`INSERT INTO run_results (run_id, data) VALUES (${runId}::uuid, ${JSON.stringify(data)}::jsonb) ON CONFLICT (run_id) DO UPDATE SET data=EXCLUDED.data`
    return true
  })
}

export async function failFenced({ runId, workerId, attempt, status = 'FAILED', errorCode = 'TOOL_FAILED', message = 'Request failed', data = null, summary = {} }) {
  if (!terminal.has(status)) throw new Error('invalid terminal status')
  return prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw`UPDATE tool_runs SET status=${status}::"RunStatus", error_code=${errorCode}, error_message=${message}, summary=${JSON.stringify(summary)}::jsonb, finished_at=now() WHERE id=${runId}::uuid AND status='RUNNING' AND worker_id=${workerId} AND attempt=${attempt} RETURNING id`
    if (!rows.length) return false
    if (data !== null) await tx.$queryRaw`INSERT INTO run_results (run_id, data) VALUES (${runId}::uuid, ${JSON.stringify(data)}::jsonb) ON CONFLICT (run_id) DO UPDATE SET data=EXCLUDED.data`
    return true
  })
}

export async function cancelQueued(runId, userId) { const rows = await prisma.$queryRaw`UPDATE tool_runs SET status='CANCELLED', finished_at=now() WHERE id=${runId}::uuid AND user_id=${userId}::uuid AND status='QUEUED' RETURNING id, attempt, quota_date`; return rows[0] ?? null }
export async function requestCancel(runId, userId) { const rows = await prisma.$queryRaw`UPDATE tool_runs SET cancel_requested_at=now() WHERE id=${runId}::uuid AND user_id=${userId}::uuid AND status='RUNNING' AND cancel_requested_at IS NULL RETURNING id`; return Boolean(rows.length) }
export async function countActiveForUser(userId) { const rows = await prisma.$queryRaw`SELECT count(*)::int AS n FROM tool_runs WHERE user_id=${userId}::uuid AND status IN ('QUEUED','RUNNING')`; return Number(rows[0]?.n ?? 0) }
export async function refundOnce(runId) {
  return prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw`UPDATE tool_runs SET quota_refunded=true WHERE id=${runId}::uuid AND quota_date IS NOT NULL AND NOT quota_refunded RETURNING user_id, tool, quota_date, options`
    if (!rows.length) return false
    const units = rows[0].options?.plan?.unitsCount ?? (rows[0].tool === 'GEOIP_BULK' ? Math.max(1, rows[0].options?.targets?.length ?? 1) : 1)
    await tx.$queryRaw`UPDATE usage_counters SET used=GREATEST(used-${units},0), updated_at=now() WHERE user_id=${rows[0].user_id} AND tool=${rows[0].tool} AND usage_date=${rows[0].quota_date} RETURNING used`
    return true
  })
}

export async function reclaimStale({ stallSec, maxAttempts, limit = 100 }) {
  return prisma.$queryRaw`WITH s AS (SELECT id FROM tool_runs WHERE status='RUNNING' AND heartbeat_at < now() - make_interval(secs => ${stallSec}) ORDER BY heartbeat_at LIMIT ${limit} FOR UPDATE SKIP LOCKED) UPDATE tool_runs t SET status=CASE WHEN t.attempt < ${maxAttempts} THEN 'QUEUED'::"RunStatus" ELSE 'TIMED_OUT'::"RunStatus" END, worker_id=NULL, heartbeat_at=NULL, queued_at=CASE WHEN t.attempt < ${maxAttempts} THEN now() ELSE t.queued_at END, finished_at=CASE WHEN t.attempt < ${maxAttempts} THEN NULL ELSE now() END, error_code=CASE WHEN t.attempt < ${maxAttempts} THEN NULL ELSE 'WORKER_LOST' END FROM s WHERE t.id=s.id RETURNING t.id, t.status, t.attempt, t.user_id, t.tool, t.quota_date`
}

export async function markEnqueueFailed(runId) { return prisma.$queryRaw`UPDATE tool_runs SET status='FAILED', error_code='QUEUE_ERROR', error_message='Request failed', finished_at=now() WHERE id=${runId}::uuid AND status='QUEUED' RETURNING id` }

export async function findOrphanQueued(olderThanSec, limit = 100) { return prisma.$queryRaw`SELECT id, attempt, user_id, tool, quota_date FROM tool_runs WHERE status='QUEUED' AND queued_at < now() - make_interval(secs => ${olderThanSec}) ORDER BY queued_at LIMIT ${limit}` }
export async function failStaleQueued(olderThanSec, limit = 100) { return prisma.$queryRaw`WITH s AS (SELECT id FROM tool_runs WHERE status='QUEUED' AND queued_at < now() - make_interval(secs => ${olderThanSec}) ORDER BY queued_at LIMIT ${limit} FOR UPDATE SKIP LOCKED) UPDATE tool_runs t SET status='FAILED', error_code='QUEUE_TIMEOUT', error_message='Request failed', finished_at=now() FROM s WHERE t.id=s.id RETURNING t.id, t.quota_date` }
export async function findOverlong(maxRunSec, limit = 100) { return prisma.$queryRaw`SELECT id, worker_id, attempt, quota_date FROM tool_runs WHERE status='RUNNING' AND started_at < now() - make_interval(secs => ${maxRunSec}) ORDER BY started_at LIMIT ${limit}` }
export async function countQueuedBefore(queuedAt) { const rows = await prisma.$queryRaw`SELECT count(*)::int AS n FROM tool_runs WHERE status='QUEUED' AND queued_at < ${queuedAt}`; return Number(rows[0]?.n ?? 0) }
export async function requeueOwn({ runId, workerId, attempt }) { const rows = await prisma.$queryRaw`UPDATE tool_runs SET status='QUEUED', worker_id=NULL, heartbeat_at=NULL, queued_at=now() WHERE id=${runId}::uuid AND status='RUNNING' AND worker_id=${workerId} AND attempt=${attempt} RETURNING id, attempt`; return rows[0] ?? null }

export async function start({ userId, tool, target, targetKey, options = {}, quotaDate = null }) {
  return prisma.toolRun.create({ data: { userId, tool, target: String(target).slice(0, 255), targetKey, options, status: 'RUNNING', startedAt: new Date(), workerId: `inline:${process.pid}`, attempt: 1, quotaDate } })
}

export async function complete(id, { data, summary = {} }) {
  return prisma.$transaction(async (tx) => {
    await tx.runResult.create({ data: { runId: id, data } })
    return tx.toolRun.update({ where: { id }, data: { status: 'COMPLETED', summary, progressPct: 100, finishedAt: new Date() } })
  })
}

export async function fail(id, { status = 'FAILED', errorCode = 'TOOL_FAILED', message = 'Request failed' } = {}) {
  return prisma.toolRun.update({ where: { id }, data: { status, errorCode, errorMessage: message, finishedAt: new Date() } })
}

export function findRecentCompleted({ userId, tool, targetKey, options, withinSec }) {
  return prisma.toolRun.findFirst({ where: { userId, tool, targetKey, status: 'COMPLETED', options: { equals: options }, createdAt: { gte: new Date(Date.now() - withinSec * 1000) } }, include: { result: true }, orderBy: { createdAt: 'desc' } })
}

export function findByIdForUser(id, userId) {
  return prisma.toolRun.findFirst({ where: { id, userId }, include: { result: true } })
}

export function findOwnedMeta(id, userId) {
  return prisma.toolRun.findFirst({
    where: { id, userId },
    select: { id: true, tool: true, status: true },
  })
}

export function listForUser({ userId, tool, status, limit = 50, cursor } = {}) {
  const where = { userId, ...(tool ? { tool } : {}), ...(status ? { status } : {}) }
  if (cursor?.createdAt && cursor?.id) {
    const createdAt = new Date(cursor.createdAt)
    where.OR = [
      { createdAt: { lt: createdAt } },
      { createdAt, id: { lt: cursor.id } },
    ]
  }
  return prisma.toolRun.findMany({
    where,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: Math.min(50, Math.max(1, limit)),
  })
}

export async function deleteForUser(id, userId) {
  const result = await prisma.toolRun.deleteMany({ where: { id, userId } })
  return result.count > 0
}

export async function deleteTerminalForUser(userId, tools = null) {
  const result = await prisma.toolRun.deleteMany({
    where: {
      userId,
      status: { in: ['COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED'] },
      ...(tools ? { tool: { in: tools } } : {}),
    },
  })
  return result.count
}
