// Express already resolves the client IP using the `trust proxy` setting from
// Phase 1. Never parse X-Forwarded-For by hand.
export function clientIp(req) {
  return req.ip ?? null
}
