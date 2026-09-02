"""
CSRF Demo & Mitigation Tool
Author: Siddhesh Malekar

A small Flask app that demonstrates:
  1. A VULNERABLE money-transfer endpoint (no CSRF protection)
  2. The same endpoint PROTECTED with a CSRF token + SameSite cookie

Run:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000/
"""

import secrets
from flask import Flask, render_template, request, session, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Force session cookie to behave like a "Lax" real-world cookie so the demo
# is realistic. We toggle SameSite off for the vulnerable route on purpose
# by using a SEPARATE cookie-less "legacy_balance" trick — see notes below.
app.config.update(
    SESSION_COOKIE_SAMESITE="None",   # modern browsers already block a lot of CSRF via this
    SESSION_COOKIE_SECURE=False,     # would be True in production (HTTPS)
)

# ---- Fake in-memory "database" ----
USERS = {
    "alice": {"password": "password123", "balance": 1000},
}


def current_user():
    return session.get("user")


@app.route("/")
def home():
    return render_template("home.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = USERS.get(username)
        if user and user["password"] == password:
            session["user"] = username
            session["csrf_token"] = secrets.token_hex(16)
            flash("Logged in successfully.")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        user=user,
        balance=USERS[user]["balance"],
        csrf_token=session.get("csrf_token"),
    )


# ------------------------------------------------------------------
# VULNERABLE ENDPOINT
# No CSRF token check at all. Any site can build a form/img/fetch that
# POSTs here and, as long as the victim's browser sends their session
# cookie, the transfer succeeds silently.
# ------------------------------------------------------------------
@app.route("/transfer/vulnerable", methods=["POST"])
def transfer_vulnerable():
    user = current_user()
    if not user:
        return "Not logged in", 401

    amount = int(request.form.get("amount", 0))
    to = request.form.get("to", "attacker")

    USERS[user]["balance"] -= amount
    return f"[VULNERABLE] Transferred {amount} to {to}. New balance: {USERS[user]['balance']}"


# ------------------------------------------------------------------
# PROTECTED ENDPOINT
# Validates a per-session CSRF token that must be present in the form
# body. An attacker's cross-origin page cannot read this token (same-
# origin policy blocks it), so it cannot forge a valid request.
# ------------------------------------------------------------------
@app.route("/transfer/protected", methods=["POST"])
def transfer_protected():
    user = current_user()
    if not user:
        return "Not logged in", 401

    submitted_token = request.form.get("csrf_token")
    real_token = session.get("csrf_token")

    if not submitted_token or submitted_token != real_token:
        return "CSRF token missing or invalid — request blocked.", 403

    amount = int(request.form.get("amount", 0))
    to = request.form.get("to", "attacker")

    USERS[user]["balance"] -= amount
    return f"[PROTECTED] Transferred {amount} to {to}. New balance: {USERS[user]['balance']}"


if __name__ == "__main__":
    app.run(debug=True, port=5000)
