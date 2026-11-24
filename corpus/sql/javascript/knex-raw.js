const express = require('express')
const knex = require('knex')({ client: 'mysql2' })
const app = express()

app.get('/items', async (req, res) => {
  const rows = await knex.raw(`SELECT id, label FROM items WHERE label = '${req.query.label}'`) // MACSEC-SQLI
  res.json(rows)
})
