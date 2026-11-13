import { prisma } from '../db/client.js'
import { env as defaultEnv } from '../config/env.js'

export async function runRetention({ env = defaultEnv, now = new Date() } = {}) {
  const freeCutoff = new Date(now.getTime() - env.RETENTION_DAYS_FREE * 86400000)
  const paidCutoff = new Date(now.getTime() - env.RETENTION_DAYS_PAID * 86400000)
  if (env.RETENTION_DRY_RUN) {
    const rows = await prisma.$queryRaw`SELECT count(*)::int AS n FROM tool_runs r JOIN users u ON u.id=r.user_id WHERE r.status IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT') AND ((u.tier='FREE' AND r.created_at < ${freeCutoff}) OR (u.tier='PAID' AND r.created_at < ${paidCutoff}))`
    return { toolRuns: Number(rows[0]?.n ?? 0), dryRun: true }
  }
  const shareLinks = await prisma.$executeRaw`DELETE FROM share_links WHERE expires_at < now()`
  let deleted = 0
  for (let batch = 0; batch < env.RETENTION_MAX_BATCHES; batch += 1) {
    const result = await prisma.$executeRaw`DELETE FROM tool_runs WHERE id IN (SELECT r.id FROM tool_runs r JOIN users u ON u.id=r.user_id WHERE r.status IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT') AND ((u.tier='FREE' AND r.created_at < ${freeCutoff}) OR (u.tier='PAID' AND r.created_at < ${paidCutoff})) ORDER BY r.created_at LIMIT ${env.RETENTION_BATCH_SIZE})`
    deleted += result
    if (result < env.RETENTION_BATCH_SIZE) break
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  return { toolRuns: deleted, shareLinks, dryRun: false }
}

export async function runCacheSweep({ env = defaultEnv } = {}) {
  if (env.RETENTION_DRY_RUN) return { serviceCveLookups: 0, cves: 0, dryRun: true }
  const service = await prisma.$executeRaw`DELETE FROM service_cve_lookups WHERE expires_at < now()`
  const cves = await prisma.$executeRaw`DELETE FROM cves WHERE expires_at < now() AND NOT EXISTS (SELECT 1 FROM finding_cves WHERE finding_cves.cve_id = cves.id)`
  return { serviceCveLookups: service, cves, dryRun: false }
}
