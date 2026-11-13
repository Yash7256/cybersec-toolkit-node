import Redis from 'ioredis'
import { env as defaultEnv } from '../config/env.js'

export function createQueueConnection({ url = defaultEnv.REDIS_URL, worker = false } = {}) {
  return new Redis(url, {
    enableOfflineQueue: !worker,
    maxRetriesPerRequest: worker ? null : 1,
    connectTimeout: 3000,
    retryStrategy: (attempt) => Math.min(attempt * 200, 5000),
  })
}

let producer
let worker
export function getProducerConnection() { return producer ??= createQueueConnection() }
export function getWorkerConnection() { return worker ??= createQueueConnection({ worker: true }) }
export async function closeQueueConnections() {
  await Promise.all([producer?.quit().catch(() => {}), worker?.quit().catch(() => {})])
  producer = null; worker = null
}
