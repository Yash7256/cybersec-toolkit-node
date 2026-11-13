import { metrics } from './metrics.js'

export default function httpMetrics() {
  return (req, res, next) => {
    if (req.path === '/metrics') return next()
    const started = process.hrtime.bigint()
    res.once('finish', () => {
      const durationSec = Number(process.hrtime.bigint() - started) / 1e9
      const route = req.route?.path ? `${req.baseUrl}${req.route.path}` : 'unmatched'
      metrics.observeHttp({ method: req.method, route, status: res.statusCode, durationSec })
    })
    next()
  }
}
