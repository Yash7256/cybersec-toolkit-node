import { describe, it, expect, afterAll } from 'vitest'
import { enqueueRun, getRunsQueue, closeQueues } from '../../src/queue/queues.js'
import { getProducerConnection } from '../../src/queue/connections.js'

const env = { ...process.env, QUEUE_PREFIX: 'cst_phase6_test' }
const opts = { env }

describe('Phase 6 BullMQ queue', () => {
  afterAll(async () => { await closeQueues() })

  it('stores only runId and deduplicates job ids', async () => {
    const queue = getRunsQueue(opts)
    await queue.drain(true)
    const runId = '11111111-1111-4111-8111-111111111111'
    await enqueueRun({ ...opts, runId, attempt: 1, priority: 10 })
    await enqueueRun({ ...opts, runId, attempt: 1, priority: 10 })
    const job = await queue.getJob(`${runId}-1`)
    expect(job.data).toEqual({ runId })
    expect(await queue.getJobCounts('waiting', 'prioritized').then((x) => (x.waiting ?? 0) + (x.prioritized ?? 0))).toBe(1)
  })

  it('producer connection is live for integration runs', async () => {
    expect(await getProducerConnection().ping()).toBe('PONG')
  })
})
