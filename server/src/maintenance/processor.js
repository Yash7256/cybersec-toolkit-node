import { runReaper } from './reaper.js'
import { runRetention, runCacheSweep } from './retention.js'
export async function processMaintenance(job, deps = {}) {
  if (job.name === 'reaper') return runReaper(deps)
  if (job.name === 'retention') return runRetention(deps)
  if (job.name === 'cache-sweep') return runCacheSweep(deps)
  deps.logger?.warn?.({ name: job.name }, 'unknown maintenance job')
  return null
}
