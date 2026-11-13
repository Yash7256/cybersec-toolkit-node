import { describe, it, expect } from 'vitest'
import { fork } from 'node:child_process'
import { request } from 'node:http'
import { fileURLToPath } from 'node:url'

function get(url) { return new Promise((resolve, reject) => { const req = request(url, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)) }); req.on('error', reject); req.end() }) }

describe('worker graceful shutdown', () => {
  it('starts a local health server and exits cleanly on SIGTERM', async () => {
    const workerPath = fileURLToPath(new URL('../../src/worker.js', import.meta.url))
    const child = fork(workerPath, [], { env: { ...process.env, NODE_ENV: 'test', WORKER_HEALTH_PORT: '3302', REDIS_URL: 'redis://localhost:6379/1', DATABASE_URL: 'postgresql://cybersec:cybersec@localhost:5433/cybersec_test', DIRECT_URL: 'postgresql://cybersec:cybersec@localhost:5433/cybersec_test', CLERK_PUBLISHABLE_KEY: 'pk_test_x', CLERK_SECRET_KEY: 'sk_test_x', CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_test_secret_value_123', LOG_LEVEL: 'silent' }, stdio: 'ignore' })
    await new Promise((resolve, reject) => { const deadline = setTimeout(() => reject(new Error('worker health timeout')), 5000); const poll = async () => { try { if ((await get('http://127.0.0.1:3302/health')) === 200) { clearTimeout(deadline); resolve() } else setTimeout(poll, 100) } catch { setTimeout(poll, 100) } }; poll() })
    const exited = new Promise((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })))
    child.kill('SIGTERM')
    await expect(exited).resolves.toMatchObject({ code: 0 })
  }, 15000)
})
