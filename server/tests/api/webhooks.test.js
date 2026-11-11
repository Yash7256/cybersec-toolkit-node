import { describe, it, expect, beforeEach } from 'vitest'
import { randomUUID } from 'node:crypto'
import { Router } from 'express'
import request from 'supertest'
import { Webhook } from 'svix'
import { prisma } from '../../src/db/client.js'
import { handleClerkEvent } from '../../src/services/clerkSync.js'
import webhookRouter from '../../src/routes/webhooks.js'
import { truncateAll } from '../db/helpers.js'
import { makeTestApp, makeTestAuth } from '../helpers/auth.js'

const TEST_SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'

function buildWebhookApp(handler = handleClerkEvent) {
  return makeTestApp({
    auth: makeTestAuth(),
    webhooks: webhookRouter({ handler }),
  })
}

function signedRequest(
  payload,
  { msgId = randomUUID(), timestamp = new Date(), tamper } = {}
) {
  const seconds = Math.floor(timestamp.getTime() / 1000)
  const tsDate = new Date(seconds * 1000)
  const body = JSON.stringify(payload)
  const signature = new Webhook(TEST_SECRET).sign(msgId, tsDate, body)

  return {
    id: msgId,
    headers: {
      'svix-id': msgId,
      'svix-timestamp': String(seconds),
      'svix-signature': signature,
      'content-type': 'application/json',
    },
    body: tamper ?? body,
  }
}

function send(app, signed) {
  return request(app).post('/api/webhooks/clerk').set(signed.headers).send(signed.body)
}

function userEvent(type, { id = 'clerk_wh_1', email = 'Wh@Example.TEST', tier = 'free' } = {}) {
  return {
    type,
    data: {
      id,
      email_addresses: [{ id: `${id}_email`, email_address: email }],
      primary_email_address_id: `${id}_email`,
      public_metadata: { tier },
    },
  }
}

describe('clerk webhooks', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('processes a valid user.created exactly once', async () => {
    const app = buildWebhookApp()
    const signed = signedRequest(userEvent('user.created'))

    const res = await send(app, signed)

    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({ received: true, duplicate: false, handled: true })

    const user = await prisma.user.findUnique({ where: { clerkUserId: 'clerk_wh_1' } })
    expect(user.email).toBe('wh@example.test')

    const event = await prisma.webhookEvent.findUnique({ where: { id: signed.id } })
    expect(event.processedAt).not.toBeNull()
    expect(await prisma.auditLog.count({ where: { action: 'user.created' } })).toBe(1)
  })

  it('treats a replayed svix-id as a duplicate', async () => {
    const app = buildWebhookApp()
    const signed = signedRequest(userEvent('user.created'))

    expect((await send(app, signed)).status).toBe(200)
    const replay = await send(app, signed)

    expect(replay.status).toBe(200)
    expect(replay.body.duplicate).toBe(true)
    expect(await prisma.user.count({ where: { clerkUserId: 'clerk_wh_1' } })).toBe(1)
    expect(await prisma.webhookEvent.count({ where: { id: signed.id } })).toBe(1)
  })

  it('rejects a tampered body, missing headers and an old timestamp', async () => {
    const app = buildWebhookApp()
    const payload = userEvent('user.created')

    const tampered = signedRequest(payload, {
      tamper: JSON.stringify({ ...payload, type: 'user.deleted' }),
    })
    expect((await send(app, tampered)).body.error.code).toBe('INVALID_SIGNATURE')

    const valid = signedRequest(payload)
    const missing = await request(app)
      .post('/api/webhooks/clerk')
      .set('content-type', 'application/json')
      .send(valid.body)
    expect(missing.status).toBe(400)
    expect(missing.body.error.code).toBe('INVALID_SIGNATURE')

    const old = signedRequest(payload, {
      timestamp: new Date(Date.now() - 10 * 60 * 1000),
    })
    expect((await send(app, old)).status).toBe(400)

    expect(await prisma.user.count()).toBe(0)
    expect(await prisma.webhookEvent.count()).toBe(0)
  })

  it('upserts out-of-order user.updated and syncs tiers', async () => {
    const app = buildWebhookApp()

    await send(app, signedRequest(userEvent('user.updated', { id: 'clerk_upd', tier: 'paid' })))
    let user = await prisma.user.findUnique({ where: { clerkUserId: 'clerk_upd' } })
    expect(user.tier).toBe('PAID')

    await send(app, signedRequest(userEvent('user.updated', { id: 'clerk_upd', tier: 'free' })))
    user = await prisma.user.findUnique({ where: { clerkUserId: 'clerk_upd' } })
    expect(user.tier).toBe('FREE')

    const changed = await prisma.auditLog.findMany({ where: { action: 'tier.changed' } })
    expect(changed).toHaveLength(1)
    expect(changed[0].metadata).toMatchObject({ from: 'PAID', to: 'FREE' })
  })

  it('soft-deletes on user.deleted and frees the email', async () => {
    const app = buildWebhookApp()

    await send(app, signedRequest(userEvent('user.created', { id: 'clerk_del' })))
    await send(app, signedRequest(userEvent('user.deleted', { id: 'clerk_del' })))

    const deleted = await prisma.user.findUnique({ where: { clerkUserId: 'clerk_del' } })
    expect(deleted.deletedAt).not.toBeNull()
    expect(deleted.email).toBeNull()
    expect(await prisma.auditLog.count({ where: { action: 'user.deleted' } })).toBe(1)

    const again = await send(
      app,
      signedRequest(userEvent('user.created', { id: 'clerk_del_2', email: 'Wh@Example.TEST' }))
    )
    expect(again.status).toBe(200)
    const fresh = await prisma.user.findUnique({ where: { clerkUserId: 'clerk_del_2' } })
    expect(fresh.email).toBe('wh@example.test')
  })

  it('returns 500 on handler failure and retries the same svix-id', async () => {
    let first = true
    const flaky = async (event, deps) => {
      if (first) {
        first = false
        throw new Error('forced failure')
      }
      return handleClerkEvent(event, deps)
    }
    const app = buildWebhookApp(flaky)
    const signed = signedRequest(userEvent('user.created', { id: 'clerk_flaky' }))

    const failed = await send(app, signed)
    expect(failed.status).toBe(500)

    const afterFail = await prisma.webhookEvent.findUnique({ where: { id: signed.id } })
    expect(afterFail.processedAt).toBeNull()
    expect(afterFail.error).toContain('forced failure')
    expect(await prisma.user.count()).toBe(0)

    const retry = await send(app, signed)
    expect(retry.status).toBe(200)

    const afterRetry = await prisma.webhookEvent.findUnique({ where: { id: signed.id } })
    expect(afterRetry.processedAt).not.toBeNull()
    expect(afterRetry.error).toBeNull()
    expect(await prisma.user.count({ where: { clerkUserId: 'clerk_flaky' } })).toBe(1)
  })

  it('ignores unknown event types with 200', async () => {
    const app = buildWebhookApp()
    const res = await send(app, signedRequest({ type: 'organization.created', data: {} }))

    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({ received: true, handled: false })
    expect(await prisma.user.count()).toBe(0)
  })

  it('parses webhook bodies as a raw Buffer, not express.json', async () => {
    const probe = Router()
    probe.post('/probe', (req, res) => res.json({ isBuffer: Buffer.isBuffer(req.body) }))
    const app = makeTestApp({ auth: makeTestAuth(), webhooks: probe })

    const res = await request(app)
      .post('/api/webhooks/probe')
      .set('content-type', 'application/json')
      .send('{"a":1}')

    expect(res.status).toBe(200)
    expect(res.body.isBuffer).toBe(true)
  })
})
