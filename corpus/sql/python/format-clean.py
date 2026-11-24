import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect('shop.db')

@app.route('/name')
def name():
    who = request.args.get('who', '')
    return str(db.execute('SELECT id FROM users WHERE name = ?', (who,)).fetchall())
