# CSRF Demo & Mitigation Tool

**Author:** Siddhesh Malekar

A minimal Flask application demonstrating a Cross-Site Request Forgery
(CSRF) attack and its mitigation using CSRF tokens and `SameSite` cookies.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/` in your browser.

## Demo credentials

- Username: `alice`
- Password: `password123`

## How to run the demo

1. Log in at `http://127.0.0.1:5000/login`.
2. Go to the Dashboard — you'll see two transfer forms:
   - **Vulnerable Transfer** → posts to `/transfer/vulnerable` (no protection)
   - **Protected Transfer** → posts to `/transfer/protected` (CSRF token required)
3. While still logged in in the SAME browser, open `attacker/attacker.html`
   directly from disk (double-click it, or `open attacker/attacker.html`).
4. Wait 2 seconds — the page auto-submits a hidden form to the vulnerable
   endpoint. Go back to the dashboard and refresh: your balance dropped,
   even though you never clicked anything on the attacker page.
5. Try building a similar hidden form pointed at `/transfer/protected`.
   It will fail with `403 CSRF token missing or invalid`, because the
   attacker page has no way to read your session's CSRF token.

## What's protecting the safe endpoint

- **CSRF token**: a random token generated at login and stored server-side
  in the session. The protected form embeds it as a hidden field; the
  server compares the submitted token against the session's token on every
  request. A cross-origin attacker page cannot read this value due to the
  browser's same-origin policy.
- **SameSite=Lax cookies**: configured on the Flask session cookie so
  that, even for basic cross-site POSTs, modern browsers restrict when
  the cookie is sent at all — a second layer of defense.

## Project structure

```
csrf-demo/
├── app.py                     # Flask app: login, dashboard, vulnerable & protected routes
├── requirements.txt
├── templates/
│   ├── home.html
│   ├── login.html
│   └── dashboard.html
└── attacker/
    └── attacker.html          # Simulated malicious page exploiting the vulnerable route
```
