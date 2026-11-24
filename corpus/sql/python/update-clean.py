import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect('shop.db')

@app.route('/rename')
def rename():
    who = request.args.get('who', '')
    db.execute('UPDATE users SET seen = 1 WHERE name = ?', (who,))
    return 'ok'
