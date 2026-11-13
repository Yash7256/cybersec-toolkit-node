import { validateTarget } from '../security/targetPolicy.js'
import { capResult } from '../tools/_shared/truncate.js'
import { ToolError } from '../tools/_shared/errors.js'

export async function executeRun({ run, definition, signal = new AbortController().signal, onProgress = () => {}, env }) {
  let target = { targetKey: run.targetKey, addresses: [] }
  if (definition.touchesTarget) {
    try { target = await validateTarget(run.target, { env }) } catch { return { status: 'COMPLETED', data: { ...definition.emptyResult({ target: run.target }), error: 'Target is not allowed' }, summary: { error: 'Target is not allowed' }, blocked: true } }
  }
  try {
    const data = await Promise.race([
      definition.execute({ target: run.target, ...(run.options ?? {}) }, { signal, target, reportProgress: onProgress, env }),
      new Promise((_, reject) => signal.addEventListener('abort', () => reject(new ToolError(signal.reason === 'cancelled' ? 'cancelled' : 'timeout', 'Request failed')), { once: true })),
    ])
    return { status: 'COMPLETED', data: capResult(data), summary: definition.summarize(data) }
  } catch (err) {
    const toolErr = err instanceof ToolError ? err : new ToolError('internal', 'Request failed', err)
    if (toolErr.kind === 'target') return { status: 'COMPLETED', data: { ...definition.emptyResult(run.options ?? { target: run.target }), error: toolErr.message }, summary: { error: toolErr.message } }
    if (toolErr.kind === 'cancelled') return { status: 'CANCELLED', errorCode: 'CANCELLED', errorMessage: 'Run cancelled', summary: { error: 'Run cancelled' } }
    return { status: toolErr.kind === 'timeout' ? 'TIMED_OUT' : 'FAILED', errorCode: toolErr.kind === 'timeout' ? 'TOOL_TIMEOUT' : 'UPSTREAM_ERROR', errorMessage: toolErr.message, summary: { error: toolErr.message } }
  }
}
