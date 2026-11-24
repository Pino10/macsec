const express = require('express')
const knex = require('knex')({ client: 'mysql2' })
const app = express()

app.get('/items', async (req, res) => {
  const rows = await knex('items').where('label', req.query.label)
  res.json(rows)
})
