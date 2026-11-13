import { z } from 'zod'
import { parsePorts } from '../../security/ports.js'
import { MAX_PORTS_PER_SCAN, MAX_PORT_RANGE_SPAN } from '../../config/limits.js'

const portValueSchema = z.union([z.number(), z.string()])

function invalidPort(ctx, message = 'Port specification is invalid.') {
  ctx.addIssue({ code: 'custom', message })
  return z.NEVER
}

const baseSchema = z.object({
    target: z.string().trim().min(1).max(253),
    ports: z.union([z.string(), z.array(portValueSchema)]).optional(),
    start_port: z.coerce.number().int().min(1).max(65535).optional(),
    end_port: z.coerce.number().int().min(1).max(65535).optional(),
    timeout: z.coerce.number().min(0.1).max(10).default(2),
    max_concurrent: z.coerce.number().int().min(1).max(2000).default(100),
    include_ai_recommendations: z.boolean().default(true),
    include_threat_intel: z.boolean().default(true),
    include_misconfigurations: z.boolean().default(true),
    include_screenshots: z.boolean().default(true),
})

export const inputShape = baseSchema.shape

export const schema = baseSchema
  .superRefine((value, ctx) => {
    const hasPorts = value.ports !== undefined && value.ports !== null
    const hasStart = value.start_port !== undefined && value.start_port !== null
    const hasEnd = value.end_port !== undefined && value.end_port !== null

    if (hasPorts && (hasStart || hasEnd)) {
      ctx.addIssue({
        code: 'custom',
        path: ['ports'],
        message: 'Provide either ports or start_port/end_port, not both.',
      })
      return
    }
    if (hasStart !== hasEnd) {
      ctx.addIssue({
        code: 'custom',
        path: hasStart ? ['end_port'] : ['start_port'],
        message: 'start_port and end_port must be provided together.',
      })
      return
    }
    if (hasStart && value.end_port < value.start_port) {
      ctx.addIssue({ code: 'custom', path: ['end_port'], message: 'end_port must be >= start_port.' })
      return
    }
    if (hasStart && value.end_port - value.start_port + 1 > MAX_PORT_RANGE_SPAN) {
      ctx.addIssue({ code: 'custom', path: ['end_port'], message: 'Port range is too large.' })
      return
    }
    if (hasPorts) {
      try {
        const resolved = parsePorts(value.ports)
        if (resolved.length > MAX_PORTS_PER_SCAN) invalidPort(ctx, 'Too many ports requested.')
      } catch {
        invalidPort(ctx)
      }
    }
  })
  .transform((value) => {
    const hasPorts = value.ports !== undefined && value.ports !== null
    const hasRange =
      value.start_port !== undefined && value.start_port !== null &&
      value.end_port !== undefined && value.end_port !== null

    let ports = null
    if (hasPorts) ports = parsePorts(value.ports)
    else if (hasRange) {
      ports = []
      for (let port = value.start_port; port <= value.end_port; port += 1) ports.push(port)
    }

    return {
      ...value,
      start_port: value.start_port ?? null,
      end_port: value.end_port ?? null,
      ports,
    }
  })
