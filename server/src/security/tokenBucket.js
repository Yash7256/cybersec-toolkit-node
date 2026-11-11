export class TokenBucket {
  #ratePerSec
  #burst
  #now
  #setTimeoutFn
  #tokens
  #lastRefill
  #queue = []
  #timer = null

  constructor({
    ratePerSec,
    burst,
    now = () => Date.now(),
    setTimeoutFn = (fn, ms) => setTimeout(fn, ms),
  } = {}) {
    if (!(ratePerSec > 0)) throw new Error('TokenBucket requires ratePerSec > 0')
    if (!(burst > 0)) throw new Error('TokenBucket requires burst > 0')

    this.#ratePerSec = ratePerSec
    this.#burst = burst
    this.#now = now
    this.#setTimeoutFn = setTimeoutFn
    this.#tokens = burst
    this.#lastRefill = now()
  }

  async take(n = 1) {
    if (!(typeof n === 'number' && Number.isFinite(n) && n > 0)) {
      throw new Error('TokenBucket.take requires a positive amount')
    }
    if (n > this.#burst) {
      throw new Error(
        `TokenBucket.take(${n}) exceeds burst capacity of ${this.#burst}`
      )
    }

    return new Promise((resolve) => {
      this.#queue.push({ amount: n, resolve })
      this.#pump()
    })
  }

  #refill() {
    const now = this.#now()
    const elapsedSec = Math.max(0, (now - this.#lastRefill) / 1000)
    if (elapsedSec > 0) {
      this.#tokens = Math.min(
        this.#burst,
        this.#tokens + elapsedSec * this.#ratePerSec
      )
      this.#lastRefill = now
    }
  }

  #pump() {
    if (this.#timer !== null) return

    while (this.#queue.length > 0) {
      this.#refill()
      const head = this.#queue[0]
      if (head.amount > this.#tokens + 1e-12) {
        const waitMs = ((head.amount - this.#tokens) / this.#ratePerSec) * 1000
        this.#timer = this.#setTimeoutFn(() => {
          this.#timer = null
          this.#pump()
        }, Math.max(1, Math.ceil(waitMs)))
        return
      }

      this.#tokens -= head.amount
      this.#queue.shift()
      head.resolve()
    }
  }
}
