class AppError extends Error {
  constructor(statusCode, code, message, details) {
    super(message)
    this.name = 'AppError'
    this.statusCode = statusCode
    this.code = code
    this.isOperational = true
    if (details !== undefined) this.details = details
    Error.captureStackTrace(this, this.constructor)
  }

  static badRequest(message, details) {
    return new AppError(400, 'BAD_REQUEST', message, details)
  }

  static unauthorized(message = 'Unauthorized') {
    return new AppError(401, 'UNAUTHORIZED', message)
  }

  static forbidden(message = 'Forbidden') {
    return new AppError(403, 'FORBIDDEN', message)
  }

  static notFound(message = 'Not found') {
    return new AppError(404, 'NOT_FOUND', message)
  }

  static tooMany(message = 'Too many requests') {
    return new AppError(429, 'RATE_LIMITED', message)
  }
}

export default AppError
