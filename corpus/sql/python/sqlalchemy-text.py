from flask import Flask, request
from sqlalchemy import text
from models import session

app = Flask(__name__)

@app.route('/items')
def items():
    label = request.args.get('label', '')
    return str(session.execute(text(f"SELECT id, label FROM items WHERE label = '{label}'")).fetchall())  # MACSEC-SQLI
