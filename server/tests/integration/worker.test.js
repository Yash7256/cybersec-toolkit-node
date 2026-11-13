import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import * as userRepo from '../../src/db/repos/userRepo.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import { processRun } from '../../src/worker/processor.js'
import { truncateAll } from '../db/helpers.js'

const env = { ...process.env, WORKER_HEARTBEAT_SEC: 1, RUN_STALL_SEC: 4, TOOL_HARD_TIMEOUT_MS: 5000 }
const fake = { sleep: { name: 'sleep', toolEnum: 'DNS', touchesTarget: false, emptyResult: () => ({ error: null }), summarize: () => ({ ok: true }), async execute(input, ctx) { ctx.reportProgress(50); await new Promise((resolve) => setTimeout(resolve, 20)); return { target: input.target, ok: true } } } }

describe('Phase 6 worker processor', () => {
  beforeEach(() => truncateAll())
  afterAll(() => prisma.$disconnect())
  it('claims, executes, and persists a run through the fenced path', async () => {
    const user = await userRepo.upsertFromClerk({ clerkUserId: 'worker_test', email: 'worker_test@example.test', tier: 'FREE' })
    const run = await runRepo.createQueuedWithCap({ userId: user.id, tool: 'DNS', target: 'fixture.test', targetKey: 'fixture.test', options: { target: 'fixture.test' }, quotaDate: new Date(), cap: 2 })
    expect(await processRun({ data: { runId: run.id } }, { env, definitions: fake, logger: { warn() {}, error() {} } })).toBe(true)
    const stored = await prisma.toolRun.findUnique({ where: { id: run.id }, include: { result: true } })
    expect(stored.status).toBe('COMPLETED')
    expect(stored.result.data.ok).toBe(true)
  })
})
