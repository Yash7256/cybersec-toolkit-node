import { Router } from 'express'
import { createToolHandler } from '../tools/_shared/toolRoute.js'
import tools from '../tools/index.js'

const CATALOGUE = {
  dns: { label: 'DNS Lookup', description: 'Resolve DNS records over public DoH resolvers.' },
  ssl: { label: 'SSL Audit', description: 'Inspect a TLS certificate and supported protocol versions.' },
  http_headers: { label: 'HTTP Headers', description: 'Audit response security headers and disclosure.' },
  whois: { label: 'WHOIS / RDAP', description: 'Look up domain registration and expiry details.' },
  geoip: { label: 'GeoIP', description: 'Geolocate a host or IP address.' },
  ping: { label: 'Ping', description: 'Measure reachability and latency over ICMP or TCP.' },
  port_scan: { label: 'Port Scan', description: 'Scan TCP ports, fingerprint services, and assess exposure.' },
  subdomain: { label: 'Subdomain Discovery', description: 'Discover and safely probe public subdomains.' },
  traceroute: { label: 'Traceroute', description: 'Trace the network path to a validated target.' },
  webapp_scan: { label: 'Web App Scanner', description: 'Run passive or authorized active web security checks.' },
}

export default function toolsRouter({ auth, clerkClient, env, limiters } = {}) {
  const router = Router()
  for (const [name, definition] of Object.entries(tools)) {
    router.post(`/${name}`, createToolHandler({ definition, auth, clerkClient, env, limiters }))
  }
  router.get('/whois', createToolHandler({ definition: tools.whois, auth, clerkClient, env, limiters }))
  router.get('/geoip', createToolHandler({ definition: tools.geoip, auth, clerkClient, env, limiters }))
  router.get('/geo', createToolHandler({ definition: tools.geoip, auth, clerkClient, env, limiters }))
  router.get('/', (_req, res) =>
    res.set('Cache-Control', 'no-store').json(
      Object.values(tools).map((tool) => ({
        name: tool.name,
        label: CATALOGUE[tool.name]?.label ?? tool.name,
        description: CATALOGUE[tool.name]?.description ?? '',
        touchesTarget: tool.touchesTarget,
        async: tool.mode === 'async',
        input: Object.entries(tool.inputShape ?? tool.schema?.shape ?? {}).map(([name, schema]) => ({
          name,
          type: schema?._def?.typeName?.replace('Zod', '').toLowerCase() ?? 'unknown',
          required: !schema?.isOptional?.(),
        })),
        dailyLimit: env?.FREE_DAILY_LIMIT ?? null,
        ...(tool.name === 'webapp_scan' ? { requiresAuthorization: true } : {}),
      }))
    )
  )
  return router
}
