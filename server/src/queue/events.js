import { getProducerConnection } from './connections.js'
import { env as defaultEnv } from '../config/env.js'
export async function publishRunEvent(runId, event, env = defaultEnv) { try { await getProducerConnection().publish(`${env.QUEUE_PREFIX}:run:${runId}`, JSON.stringify(event)) } catch {} }
