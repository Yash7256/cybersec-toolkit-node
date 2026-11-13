import { env } from './config/env.js'
import { startWorker } from './worker/index.js'
import { createWorkerHealthServer } from './worker/health.js'
import { closeQueues } from './queue/queues.js'
import { disconnect, pingDb } from './db/client.js'
import { pingRedis } from './redis/client.js'
import { startQueueMetrics } from './observability/queueMetrics.js'

const worker = startWorker({ env })
const stopQueueMetrics = startQueueMetrics({ env })
const health = createWorkerHealthServer({ env, pingRedis, pingDb })
health.listen(env.WORKER_HEALTH_PORT, '127.0.0.1')

let stopping = false
async function shutdown() {
  if (stopping) return
  stopping = true
  await worker.stop()
  stopQueueMetrics()
  health.close()
  await closeQueues()
  await disconnect()
  process.exit(0)
}

process.on('SIGTERM', shutdown)
process.on('SIGINT', shutdown)
process.on('unhandledRejection', (err) => {
  console.error('unhandled rejection', err)
  shutdown()
})
process.on('uncaughtException', (err) => {
  console.error('uncaught exception', err)
  shutdown()
})
