import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { getRunsQueue, enqueueRun, closeQueues } from '../../src/queue/queues.js'
import { getProducerConnection } from '../../src/queue/connections.js'

const env = { ...process.env, QUEUE_PREFIX: 'cst_redis_loss' }
describe('Redis loss recovery primitives', () => {
  beforeEach(async () => { await getProducerConnection().select(1); await getProducerConnection().flushdb(); await getRunsQueue({ env }).drain(true) })
  afterAll(() => closeQueues())
  it('does not preserve Redis-only jobs after a flush and accepts re-enqueue', async () => {
    const runId = '22222222-2222-4222-8222-222222222222'
    await enqueueRun({ runId, attempt: 1, env, priority: 10 })
    await getProducerConnection().flushdb()
    expect(await getRunsQueue({ env }).getJob(`${runId}-1`)).toBeUndefined()
    await enqueueRun({ runId, attempt: 2, env, priority: 10 })
    expect(await getRunsQueue({ env }).getJob(`${runId}-2`)).toBeTruthy()
  })
})
