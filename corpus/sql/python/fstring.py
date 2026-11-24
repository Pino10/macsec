import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect('shop.db')

@app.route('/search')
def search():
    name = request.args.get('name', '')
    return str(db.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall())  # MACSEC-SQLI
