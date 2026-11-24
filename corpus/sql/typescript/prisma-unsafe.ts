import express from 'express'
import { prisma } from './db'

const app = express()

app.get('/users', async (req, res) => {
  const name = String(req.query.name ?? '')
  const rows = await prisma.$queryRawUnsafe(`SELECT id, name FROM users WHERE name = '${name}'`) // MACSEC-SQLI
  res.json(rows)
})
