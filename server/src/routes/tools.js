import { Router } from 'express'
import { createToolHandler } from '../tools/_shared/toolRoute.js'
import tools from '../tools/index.js'
import { z } from 'zod'
import { createAttachUser } from '../middleware/attachUser.js'
import * as runRepo from '../db/repos/runRepo.js'
import AppError from '../utils/AppError.js'

const CATALOGUE = {
  dns: { label: 'DNS Lookup', description: 'Resolve DNS records over public DoH resolvers.' },
  ssl: { label: 'SSL Audit', description: 'Inspect a TLS certificate and supported protocol versions.' },
  http_headers: { label: 'HTTP Headers', description: 'Audit response security headers and disclosure.' },
  whois: { label: 'WHOIS / RDAP', description: 'Look up domain registration and expiry details.' },
  geoip: { label: 'GeoIP', description: 'Geolocate a host or IP address.' },
  asn: { label: 'ASN Lookup', description: 'Inspect an autonomous system, its name, and announced prefixes.' },
  geoip_bulk: { label: 'GeoIP Bulk', description: 'Geolocate up to 100 hosts or IPs with an aggregate summary.' },
  geoip_cidr: { label: 'GeoIP CIDR', description: 'Geolocate a CIDR block up to /24 IPv4 or /120 IPv6.' },
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
  const geoipMe = {
    ...tools.geoip,
    name: 'geoip_me',
    schema: z.object({}),
    normalize: () => ({}),
    prepare: (input, { req }) => { input.target = String(req.ip ?? '').replace(/^::ffff:/i, '') },
  }
  const attach = createAttachUser({ clerkClient })
  const GEO_TOOLS = ['GEOIP', 'GEOIP_BULK', 'GEOIP_CIDR', 'ASN']
  router.get('/geoip/history', auth.requireAuth, attach, async (req, res, next) => {
    try {
      const limit = req.query.limit == null ? 20 : Number(req.query.limit)
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid limit')
      const requested = req.query.tool ? String(req.query.tool).toUpperCase() : null
      if (requested && !GEO_TOOLS.includes(requested)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid tool')
      const toolsToQuery = requested ? [requested] : GEO_TOOLS
      const batches = await Promise.all(toolsToQuery.map((tool) => runRepo.listForUser({ userId: req.user.id, tool, limit })))
      const runs = batches.flat().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, limit)
      res.set('Cache-Control', 'no-store').json({ runs })
    } catch (err) { next(err) }
  })
  router.delete('/geoip/history', auth.requireAuth, attach, async (req, res, next) => {
    try {
      const deleted = await runRepo.deleteTerminalForUser(req.user.id, GEO_TOOLS)
      res.set('Cache-Control', 'no-store').json({ deleted })
    } catch (err) { next(err) }
  })
  router.get('/geoip/me', createToolHandler({ definition: geoipMe, auth, clerkClient, env, limiters }))
  router.get('/geoip', createToolHandler({ definition: tools.geoip, auth, clerkClient, env, limiters }))
  router.get('/geo', createToolHandler({ definition: tools.geoip, auth, clerkClient, env, limiters }))
  router.get('/asn', createToolHandler({ definition: tools.asn, auth, clerkClient, env, limiters }))
  router.get('/geoip/cidr', createToolHandler({ definition: tools.geoip_cidr, auth, clerkClient, env, limiters }))
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
