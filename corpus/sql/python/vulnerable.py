import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect('shop.db')

@app.route('/search')
def search():
    name = request.args.get('name', '')
    sql = "SELECT id, name FROM users WHERE name = '%s'" % name
    return str(db.execute(sql).fetchall())
