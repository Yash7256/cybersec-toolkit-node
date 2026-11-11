import { prisma } from '../../src/db/client.js'

// All 11 tables from DATABASE-DESIGN.md. Fixed list, no dynamic identifiers.
const TABLES = [
  'audit_logs',
  'webhook_events',
  'reports',
  'finding_cves',
  'service_cve_lookups',
  'cves',
  'port_findings',
  'run_results',
  'tool_runs',
  'usage_counters',
  'users',
]

export async function truncateAll() {
  await prisma.$executeRawUnsafe(
    `TRUNCATE TABLE ${TABLES.map((table) => `"${table}"`).join(', ')} RESTART IDENTITY CASCADE`
  )
}
