import express from 'express'
import { prisma } from './db'

const app = express()

app.get('/users', async (req, res) => {
  const name = String(req.query.name ?? '')
  const rows = await prisma.user.findMany({ where: { name } })
  res.json(rows)
})
