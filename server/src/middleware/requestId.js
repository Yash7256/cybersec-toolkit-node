import crypto from 'node:crypto'

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{8,64}$/

export default function requestId() {
  return (req, res, next) => {
    const inbound = req.headers['x-request-id']
    req.id = typeof inbound === 'string' && REQUEST_ID_PATTERN.test(inbound) ? inbound : crypto.randomUUID()
    res.setHeader('x-request-id', req.id)
    next()
  }
}
