import { metrics } from '../observability/metrics.js'
import { ToolError } from '../tools/_shared/errors.js'

export function createBreaker({ name, failureThreshold = 5, windowMs = 60000, openMs = 60000 }) {
  let failures = []
  let state = 'closed'
  let openedAt = 0
  let probing = false
  return {
    async exec(fn) {
      const now = Date.now()
      failures = failures.filter((time) => now - time <= windowMs)
      if (state === 'open') {
        if (now - openedAt < openMs || probing) throw new ToolError('upstream', 'Lookup service unavailable')
        probing = true
      }
      try {
        const result = await fn()
        state = 'closed'; probing = false; failures = []
        return result
      } catch (err) {
        probing = false
        failures.push(Date.now())
        if (failures.length >= failureThreshold || state === 'open') { state = 'open'; openedAt = Date.now(); metrics.recordBreakerOpen?.(name) }
        throw err
      }
    },
  }
}
