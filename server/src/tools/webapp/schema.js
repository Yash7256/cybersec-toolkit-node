import { z } from 'zod'

export const AUTH_GATE_MESSAGE =
  'You must confirm you are authorized to actively test this target before running injection payloads against it.'

function parseTarget(value, ctx) {
  const text = value.trim()
  if (!text) {
    ctx.addIssue({ code: 'custom', message: 'target is required' })
    return z.NEVER
  }
  if (/\s/.test(text)) {
    ctx.addIssue({ code: 'custom', message: 'target must not contain whitespace' })
    return z.NEVER
  }
  if (/^https?:\/\//i.test(text)) {
    try {
      const parsed = new URL(text)
      if (parsed.username || parsed.password) {
        ctx.addIssue({ code: 'custom', message: 'target must not include credentials' })
        return z.NEVER
      }
      return text
    } catch {
      ctx.addIssue({ code: 'custom', message: 'target must be a valid URL or hostname' })
      return z.NEVER
    }
  }
  if (/[/@\\?#%:]/.test(text)) {
    ctx.addIssue({ code: 'custom', message: 'target must be a valid URL or hostname' })
    return z.NEVER
  }
  return text.replace(/\.$/, '').toLowerCase()
}

export const schema = z.object({
  target: z.string().trim().min(1).max(255).transform(parseTarget),
  max_pages: z.coerce.number().int().min(1).max(100).default(20),
  active: z.boolean().default(true),
  confirm_authorized: z.boolean().optional(),
}).superRefine((value, ctx) => {
  if (value.active && value.confirm_authorized !== true) {
    ctx.addIssue({ code: 'custom', path: ['confirm_authorized'], message: AUTH_GATE_MESSAGE })
  }
})

export const inputShape = Object.freeze({
  target: { type: 'string', required: true, description: 'URL or hostname to scan' },
  max_pages: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
  active: { type: 'boolean', default: true },
  confirm_authorized: {
    type: 'boolean',
    required: true,
    description: 'Explicit authorization confirmation; must be true to run active payloads',
  },
})
