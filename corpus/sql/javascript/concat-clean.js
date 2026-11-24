const express = require('express')
const mysql = require('mysql2/promise')
const app = express()
const pool = mysql.createPool({ host: 'localhost', user: 'shop' })

app.get('/orders', async (req, res) => {
  const [rows] = await pool.query('SELECT id, total FROM orders WHERE user = ?', [req.query.user])
  res.json(rows)
})
