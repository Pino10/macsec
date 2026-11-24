from flask import Flask, request
import pymysql

app = Flask(__name__)
conn = pymysql.connect(host='localhost', user='shop', database='shop')

@app.route('/orders')
def orders():
    user = request.args.get('user', '')
    with conn.cursor() as cur:
        cur.execute('SELECT id, total FROM orders WHERE user = %s', (user,))
        return str(cur.fetchall())
