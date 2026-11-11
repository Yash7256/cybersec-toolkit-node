import 'dotenv/config'
import { defineConfig, env } from 'prisma/config'

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    // CLI/migrations use the direct connection (never a transaction pooler)
    url: env('DIRECT_URL'),
  },
})
