import { Router } from 'express'
import { z } from 'zod'
import { createToolHandler } from '../../src/tools/_shared/toolRoute.js'
import { createLimiters } from '../../src/middleware/limiters.js'
import { startWorker } from '../../src/worker/index.js'
import { closeQueues } from '../../src/queue/queues.js'
import { getProducerConnection } from '../../src/queue/connections.js'
import { makeTestApp } from './auth.js'

export const silentLogger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  fatal() {},
  trace() {},
}

export function createAsyncTestTool({ execute, mode = 'async', toolEnum = 'DNS' } = {}) {
  const calls = []
  return {
    calls,
    definition: {
      name: 'sleep_test',
      toolEnum,
      schema: z.object({
        target: z.string().min(1),
        ms: z.coerce.number().int().min(0).max(10000).default(50),
      }),
      mode,
      touchesTarget: false,
      dedupeTtlSec: 0,
      normalize: (input) => input,
      async execute(input, ctx) {
        calls.push(input)
        if (execute) return execute(input, ctx)
        await new Promise((resolve) => setTimeout(resolve, input.ms))
        return { target: input.target, slept: input.ms }
      },
      emptyResult: (input) => ({ target: input.target, slept: null }),
      summarize: (data) => ({ slept: data.slept }),
    },
  }
}

export function buildAsyncApp({ env, definition, auth, clerkClient }) {
  const limiters = createLimiters({ env, logger: silentLogger })
  const router = Router()
  router.post(
    '/__async/sleep',
    ...createToolHandler({ definition, auth, clerkClient, env, limiters })
  )
  return makeTestApp({ auth, clerkClient, env, extraRoutes: router })
}

export async function startEmbeddedWorker({ env, definitions }) {
  const worker = startWorker({ env, logger: silentLogger, definitions, concurrency: 1 })
  await worker.worker.waitUntilReady()
  return worker
}

export async function stopEmbeddedWorker(worker) {
  await worker?.stop()
}

export async function obliterateQueues(env) {
  const redis = getProducerConnection()
  const keys = await redis.keys(`${env.QUEUE_PREFIX}:*`)
  if (keys.length) await redis.del(...keys)
}

export async function closeAsyncQueues() {
  await closeQueues()
}

export async function waitFor(fn, { timeoutMs = 5000, intervalMs = 25 } = {}) {
  const started = Date.now()
  for (;;) {
    const value = await fn()
    if (value) return value
    if (Date.now() - started > timeoutMs) throw new Error('waitFor timed out')
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
}
