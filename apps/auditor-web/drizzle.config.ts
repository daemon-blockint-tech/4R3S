import { config } from 'dotenv'
import { defineConfig } from 'drizzle-kit'

// drizzle-kit runs outside Next.js — load env the same way as local dev (.env.local).
config({ path: '.env.local' })
config({ path: '.env' })

const url = process.env.POSTGRES_URL
if (!url) {
  throw new Error(
    'POSTGRES_URL is required for drizzle-kit. Copy .env.local.example to .env.local (or run `npm run db:up` from the monorepo root and set POSTGRES_URL).',
  )
}

export default defineConfig({
  schema: './lib/db/schema.ts',
  out: './lib/db/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url,
  },
})
