import AppError from '../utils/AppError.js'

export default function notFound() {
  return (req, res, next) => {
    next(AppError.notFound(`Route not found: ${req.method} ${req.originalUrl}`))
  }
}
