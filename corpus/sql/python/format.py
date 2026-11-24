import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect('shop.db')

@app.route('/name')
def name():
    who = request.args.get('who', '')
    sql = "SELECT id FROM users WHERE name = '{}'".format(who)  # MACSEC-SQLI
    return str(db.execute(sql).fetchall())
