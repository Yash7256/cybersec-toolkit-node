import { env as defaultEnv } from '../config/env.js'
import { TokenBucket } from '../security/tokenBucket.js'
import { HTTPS_PORTS } from './constants.js'
import { tryConnect as defaultTryConnect } from './connect.js'
import { probeBanner as defaultProbeBanner } from './bannerProbe.js'
import { socketSemaphore as defaultSemaphore } from './sockets.js'
import { classifyPortRisk, getPortDescription, getServiceForPort } from './portMeta.js'

function buildDetail({ port, service, probe }) {
  const [riskLevel, riskReason] = classifyPortRisk(port, service)
  const description = getPortDescription(port, service)

  return {
    port_number: port,
    service,
    status: 'open',
    version: probe.version ?? null,
    raw_banner: probe.raw_banner ?? null,
    welcome_message: probe.welcome_message ?? null,
    server_response: probe.server_response ?? null,
    risk_level: riskLevel,
    risk_reason: riskReason,
    service_description: description.purpose,
    service_security_concern: description.security_concern,
    technologies: probe.technologies ?? [],
    screenshot: null,
    screenshot_url: null,
    recommendation: null,
    recommendation_reason: null,
    recommendation_priority: null,
    mitre_attack: [],
    potential_threat: null,
    exploit_availability: {},
    misconfigurations: [],
    exposure_severity: {},
    cve_result: null,
    cve_count: 0,
    cve_critical_count: 0,
    cve_high_count: 0,
    cve_medium_count: 0,
    cve_low_count: 0,
    max_cvss_score: null,
    max_cvss_severity: null,
    max_cvss_cve: null,
    fingerprint: {},
  }
}

function abortable(promise, signal) {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(Object.assign(new Error('aborted'), { code: 'ABORT_ERR' }))
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(Object.assign(new Error('aborted'), { code: 'ABORT_ERR' }))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      (err) => {
        signal.removeEventListener('abort', onAbort)
        reject(err)
      }
    )
  })
}

export async function scanPorts({
  address,
  family,
  hostname,
  ports,
  timeoutMs = 2000,
  concurrency = defaultEnv.SCAN_DEFAULT_CONCURRENCY,
  ratePerSec = defaultEnv.SCAN_RATE_CONN_PER_SEC,
  signal,
  onProgress,
  deps = {},
}) {
  const {
    connect = defaultTryConnect,
    probe = defaultProbeBanner,
    sockets = defaultSemaphore,
    serviceForPort = getServiceForPort,
    now = Date.now,
    tokenBucket = new TokenBucket({
      ratePerSec,
      burst: 1,
      now,
      setTimeoutFn: deps.setTimeoutFn ?? ((fn, ms) => setTimeout(fn, ms)),
    }),
  } = deps

  const effectiveConcurrency = Math.max(
    1,
    Math.min(
      Number.isFinite(concurrency) ? Math.trunc(concurrency) : defaultEnv.SCAN_DEFAULT_CONCURRENCY,
      defaultEnv.SCAN_MAX_CONCURRENCY
    )
  )

  const sortedPorts = [...new Set(ports)].sort((a, b) => a - b)
  const total = sortedPorts.length
  const startedAt = now()
  const latencies = []
  const openPorts = []
  const inFlight = new Set()

  let index = 0
  let done = 0
  let closedCount = 0
  let filteredCount = 0
  let aborted = Boolean(signal?.aborted)
  let lastProgressAt = 0

  const report = (force = false) => {
    if (!onProgress) return
    const at = now()
    if (!force && at - lastProgressAt < 100 && done < total) return
    lastProgressAt = at
    try {
      onProgress(total === 0 ? 1 : done / total)
    } catch {}
  }

  const onAbort = () => {
    aborted = true
    for (const socket of inFlight) {
      try {
        socket.destroy()
      } catch {}
    }
  }
  signal?.addEventListener('abort', onAbort, { once: true })

  async function attempt(port) {
    await abortable(tokenBucket.take(), signal)
    const release = await sockets.acquire(signal)
    let socket = null

    try {
      const attemptStart = now()
      const result = await connect({
        address,
        family,
        port,
        tls: HTTPS_PORTS.has(port),
        servername: hostname,
        timeoutMs,
        signal,
      })
      latencies.push(now() - attemptStart)

      if (result.state !== 'open' || !result.socket) {
        return result.state === 'closed' ? 'closed' : 'filtered'
      }

      socket = result.socket
      inFlight.add(socket)

      if (aborted || signal?.aborted) return 'filtered'

      const service = serviceForPort(port)
      const banner = await probe({
        socket,
        port,
        address,
        hostname,
        timeoutMs,
        signal,
      })

      if (!aborted) openPorts.push(buildDetail({ port, service, probe: banner }))
      return 'open'
    } catch (err) {
      if (err?.code === 'ABORT_ERR' || signal?.aborted) aborted = true
      return 'filtered'
    } finally {
      if (socket) {
        inFlight.delete(socket)
        try {
          socket.destroy()
        } catch {}
      }
      release()
    }
  }

  async function worker() {
    while (!aborted) {
      const current = index
      index += 1
      if (current >= total) return

      let outcome = 'filtered'
      try {
        outcome = await attempt(sortedPorts[current])
      } catch {
        aborted = aborted || Boolean(signal?.aborted)
      }
      done += 1
      if (outcome === 'closed') closedCount += 1
      else if (outcome !== 'open') filteredCount += 1
      report()
    }
  }

  try {
    await Promise.all(Array.from({ length: effectiveConcurrency }, () => worker()))
  } finally {
    signal?.removeEventListener('abort', onAbort)
    for (const socket of inFlight) {
      try {
        socket.destroy()
      } catch {}
    }
    inFlight.clear()
    report(true)
  }

  const open = openPorts.sort((a, b) => a.port_number - b.port_number)
  const avgLatency =
    latencies.length > 0
      ? Math.round((latencies.reduce((sum, value) => sum + value, 0) / latencies.length) * 100) / 100
      : null

  return {
    open,
    total_scanned: total,
    open_ports_count: open.length,
    closed_count: closedCount,
    filtered_count: filteredCount,
    packets_sent: done,
    avg_latency_ms: avgLatency,
    scan_duration_seconds: Math.round(((now() - startedAt) / 1000) * 100) / 100,
    aborted: aborted || Boolean(signal?.aborted),
  }
}
