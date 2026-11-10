import express from 'express'
import cors from 'cors'

const app = express()
const PORT = process.env.PORT || 3001

app.use(cors())
app.use(express.json())

const api = express.Router()

api.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() })
})

api.get('/hello', (req, res) => {
  const name = req.query.name || 'world'
  res.json({ message: `Hello, ${name}!` })
})

app.use('/api', api)

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' })
})

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`)
})
