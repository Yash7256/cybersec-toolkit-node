import http from 'node:http'
import { createApp } from './app.js'
import { env } from './config/env.js'
import { createLogger } from './utils/logger.js'
import { registerReadinessCheck } from './routes/health.js'
import { pingDb, disconnect } from './db/client.js'
import { pingRedis, disconnectRedis, waitForReady } from './redis/client.js'
import { startEventLoopMonitor } from './observability/eventLoop.js'
import { getProducerConnection } from './queue/connections.js'
import { getQueueDepth, closeQueues } from './queue/queues.js'
import { startWorker } from './worker/index.js'
import { startQueueMetrics } from './observability/queueMetrics.js'

const logger = createLogger(env)
const app = createApp({ env, logger })
const embeddedWorker = env.RUN_EMBEDDED_WORKER ? startWorker({ env, logger }) : null
const stopQueueMetrics = startQueueMetrics({ env })
const server = http.createServer(app)

server.keepAliveTimeout = 65_000
server.headersTimeout = 66_000

const shutdownHooks = []
export function onShutdown(hook) {
  shutdownHooks.push(hook)
}

registerReadinessCheck('db', async () => {
  await pingDb()
  return 'ok'
})
onShutdown(disconnect)
onShutdown(disconnectRedis)
onShutdown(closeQueues)
onShutdown(stopQueueMetrics)
if (embeddedWorker) onShutdown(() => embeddedWorker.stop())
const disableEventLoopMonitor = startEventLoopMonitor({ logger })
onShutdown(disableEventLoopMonitor)

registerReadinessCheck('redis', async () => (await pingRedis({ timeoutMs: 1500, client: getProducerConnection() }) ? 'ok' : 'fail'))
registerReadinessCheck('queue', async () => { await getProducerConnection().ping(); await Promise.race([getQueueDepth(), new Promise((_, reject) => setTimeout(() => reject(new Error('queue timeout')), 2000))]); return 'ok' })

let shuttingDown = false
async function shutdown(signal, exitCode = 0) {
  if (shuttingDown) {
    logger.warn({ signal }, 'Shutdown already in progress')
    return
  }
  shuttingDown = true
  logger.info({ signal }, 'Shutting down gracefully')

  const forceExitTimer = setTimeout(() => {
    logger.error('Graceful shutdown timed out after 10s, forcing exit')
    process.exit(1)
  }, 10_000)
  forceExitTimer.unref()

  try {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()))
    })
    for (const hook of shutdownHooks) {
      await hook()
    }
    clearTimeout(forceExitTimer)
    logger.info('Shutdown complete')
    process.exit(exitCode)
  } catch (err) {
    logger.error({ err }, 'Error during shutdown')
    process.exit(1)
  }
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))

process.on('unhandledRejection', (reason) => {
  logger.fatal({ err: reason }, 'Unhandled rejection')
  shutdown('unhandledRejection', 1)
})

process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'Uncaught exception')
  shutdown('uncaughtException', 1)
})

waitForReady(5000).then((ready) => {
  if (!ready) logger.warn('redis degraded')
})

server.listen(env.PORT, () => {
  logger.info(`Server listening on http://localhost:${env.PORT}`)
})
