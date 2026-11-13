import { Queue } from 'bullmq'
import { getProducerConnection } from './connections.js'
import { env as defaultEnv } from '../config/env.js'

let maintenance
export function getMaintenanceQueue({ env = defaultEnv } = {}) { return maintenance ??= new Queue('maintenance', { connection: getProducerConnection(), prefix: env.QUEUE_PREFIX }) }
export async function closeMaintenanceQueue() { await maintenance?.close().catch(() => {}); maintenance = null }
