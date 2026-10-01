"""A small, deliberately-imperfect sample web service.

This is bundled sample input for ThreatForge's code analyzer - a realistic-ish
Flask app with a database and an outbound third-party call. It is intentionally
missing some controls (no rate limiting, no explicit authorization checks) so the
threat model has something to surface. It is NOT meant to be run in production.

Author: Krishita Sanjay Choksi.
"""

import sqlite3

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    # Authentication present (checks a password) but no rate limiting.
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    db = get_db()
    cur = db.execute(
        "SELECT id FROM users WHERE username=? AND password=?",
        (username, password),
    )
    row = cur.fetchone()
    if row:
        return jsonify({"status": "ok", "user_id": row[0]})
    return jsonify({"status": "denied"}), 401


@app.route("/profile/<int:user_id>", methods=["GET"])
def profile(user_id):
    # No explicit authorization check that the caller owns this user_id.
    db = get_db()
    cur = db.execute("SELECT username, email FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    return jsonify({"username": row[0], "email": row[1]})


@app.route("/pay", methods=["POST"])
def pay():
    # Outbound call to a third-party payment provider.
    data = request.get_json()
    resp = requests.post(
        "https://payments.example.com/charge",
        json={"amount": data.get("amount"), "token": data.get("token")},
        timeout=10,
    )
    return jsonify(resp.json())


if __name__ == "__main__":
    app.run()
