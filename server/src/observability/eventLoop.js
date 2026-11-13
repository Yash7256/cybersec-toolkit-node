import { monitorEventLoopDelay } from 'node:perf_hooks'
import { metrics } from './metrics.js'

export function startEventLoopMonitor({ logger = console, intervalMs = 5000 } = {}) {
  const histogram = monitorEventLoopDelay({ resolution: 20 })
  histogram.enable()
  let lastWarning = 0
  const timer = setInterval(() => {
    const p99Seconds = histogram.percentile(99) / 1e9
    metrics.setEventLoopLag(p99Seconds)
    if (p99Seconds > 0.2 && Date.now() - lastWarning >= 60_000) {
      lastWarning = Date.now()
      logger.warn({ p99Seconds }, 'event loop lag is high')
    }
    histogram.reset()
  }, intervalMs)
  timer.unref()
  return () => {
    clearInterval(timer)
    histogram.disable()
  }
}
