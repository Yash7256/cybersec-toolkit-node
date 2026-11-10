import { ZodError, z } from 'zod'
import AppError from '../utils/AppError.js'

export default function errorHandler(logger = console) {
  return (err, req, res, next) => {
    if (res.headersSent) {
      next(err)
      return
    }

    let statusCode = 500
    let code = 'INTERNAL_ERROR'
    let message = 'Internal server error'
    let details

    if (err instanceof AppError) {
      statusCode = err.statusCode
      code = err.code
      message = err.message
      if (err.details !== undefined) details = err.details
    } else if (err instanceof ZodError) {
      statusCode = 400
      code = 'VALIDATION_ERROR'
      message = 'Validation failed'
      details = z.flattenError(err)
    } else if (err instanceof SyntaxError || (err && err.type === 'entity.parse.failed')) {
      statusCode = 400
      code = 'INVALID_JSON'
      message = 'Request body is not valid JSON'
    } else if (err && err.type === 'entity.too.large') {
      statusCode = 413
      code = 'PAYLOAD_TOO_LARGE'
      message = 'Request body exceeds the allowed limit'
    } else {
      statusCode = 500
      code = 'INTERNAL_ERROR'
      message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
    }

    const logPayload = {
      err,
      reqId: req.id,
      statusCode,
      code,
    }

    if (statusCode >= 500) {
      logger.error(logPayload, message)
    } else {
      logger.warn(logPayload, message)
    }

    res.status(statusCode).json({
      error: {
        code,
        message,
        requestId: req.id,
        ...(details !== undefined && { details }),
      },
    })
  }
}
