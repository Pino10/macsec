const express = require('express')
const mysql = require('mysql2/promise')
const app = express()
const pool = mysql.createPool({ host: 'localhost', user: 'shop' })

app.get('/search', async (req, res) => {
  const sql = `SELECT id, name FROM users WHERE name = '${req.query.name}'`
  const [rows] = await pool.query(sql)
  res.json(rows)
})
