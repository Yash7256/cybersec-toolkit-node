// Idempotent development seed. Re-running changes nothing.
import 'dotenv/config'

if (process.env.NODE_ENV === 'production') {
  console.error('Refusing to seed: NODE_ENV is production')
  process.exit(1)
}

const { prisma, disconnect } = await import('../src/db/client.js')

async function upsertUser() {
  return prisma.user.upsert({
    where: { clerkUserId: 'user_dev_seed' },
    create: { clerkUserId: 'user_dev_seed', email: 'dev@example.test' },
    update: {},
  })
}

async function upsertRuns(user) {
  const dns = await prisma.toolRun.upsert({
    where: { id: '11111111-1111-7111-8111-111111111101' },
    create: {
      id: '11111111-1111-7111-8111-111111111101',
      userId: user.id,
      tool: 'DNS',
      target: 'Example.com',
      targetKey: 'example.com',
      status: 'COMPLETED',
      progressPct: 100,
      queuedAt: new Date('2026-11-01T10:00:00Z'),
      startedAt: new Date('2026-11-01T10:00:01Z'),
      finishedAt: new Date('2026-11-01T10:00:05Z'),
    },
    update: {},
  })

  const portScan = await prisma.toolRun.upsert({
    where: { id: '11111111-1111-7111-8111-111111111102' },
    create: {
      id: '11111111-1111-7111-8111-111111111102',
      userId: user.id,
      tool: 'PORT_SCAN',
      target: 'example.com',
      targetKey: 'example.com',
      status: 'COMPLETED',
      progressPct: 100,
      queuedAt: new Date('2026-11-02T11:00:00Z'),
      startedAt: new Date('2026-11-02T11:00:01Z'),
      finishedAt: new Date('2026-11-02T11:00:30Z'),
    },
    update: {},
  })

  const whois = await prisma.toolRun.upsert({
    where: { id: '11111111-1111-7111-8111-111111111103' },
    create: {
      id: '11111111-1111-7111-8111-111111111103',
      userId: user.id,
      tool: 'WHOIS',
      target: 'example.com',
      targetKey: 'example.com',
      status: 'FAILED',
      errorCode: 'WHOIS_LOOKUP_FAILED',
      errorMessage: 'Seeded failure for testing',
      progressPct: 50,
      attempt: 1,
      queuedAt: new Date('2026-11-03T12:00:00Z'),
      startedAt: new Date('2026-11-03T12:00:01Z'),
      finishedAt: new Date('2026-11-03T12:00:10Z'),
    },
    update: {},
  })

  return { dns, portScan, whois }
}

async function upsertFindings(portScan) {
  const findings = [
    { port: 22, protocol: 'TCP', state: 'OPEN', service: 'ssh', version: 'OpenSSH 9.6', risk: 'LOW' },
    { port: 80, protocol: 'TCP', state: 'OPEN', service: 'http', version: 'nginx 1.25.3', risk: 'MEDIUM' },
    { port: 443, protocol: 'TCP', state: 'OPEN', service: 'https', version: 'nginx 1.25.3', risk: 'MEDIUM' },
    { port: 3306, protocol: 'TCP', state: 'FILTERED', service: 'mysql', version: null, risk: 'INFO' },
    { port: 53, protocol: 'UDP', state: 'OPEN', service: 'domain', version: null, risk: 'INFO' },
  ]
  for (const finding of findings) {
    await prisma.portFinding.upsert({
      where: { runId_port_protocol: { runId: portScan.id, port: finding.port, protocol: finding.protocol } },
      create: { runId: portScan.id, ...finding },
      update: {},
    })
  }
}

async function upsertResult(dns) {
  await prisma.runResult.upsert({
    where: { runId: dns.id },
    create: {
      runId: dns.id,
      data: { records: [{ type: 'A', value: '93.184.216.34' }, { type: 'AAAA', value: '2606:2800:21f:cb07:6820:80da:af6b:8b2c' }], seeded: true },
    },
    update: {},
  })
}

try {
  const user = await upsertUser()
  const { dns, portScan } = await upsertRuns(user)
  await upsertFindings(portScan)
  await upsertResult(dns)
  const counts = {
    users: await prisma.user.count(),
    toolRuns: await prisma.toolRun.count(),
    portFindings: await prisma.portFinding.count(),
    runResults: await prisma.runResult.count(),
  }
  console.log('Seed complete:', counts)
} finally {
  await disconnect()
}
