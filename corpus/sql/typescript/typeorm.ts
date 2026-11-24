import express from 'express'
import { AppDataSource } from './data-source'

const app = express()

app.get('/notes', async (req, res) => {
  const title = String(req.query.title ?? '')
  const rows = await AppDataSource.query(`SELECT id, title FROM notes WHERE title = '${title}'`) // MACSEC-SQLI
  res.json(rows)
})
