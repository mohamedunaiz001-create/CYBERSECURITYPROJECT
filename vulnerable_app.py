#!/usr/bin/env python3
"""
================================================================
  vulnerable_app.py
  Internship — Task 3: Secure Coding Review
  TARGET APPLICATION (Deliberately Vulnerable for Audit)
  ⚠  FOR EDUCATIONAL / LAB USE ONLY — DO NOT DEPLOY  ⚠
================================================================

This is a simple Flask web application intentionally written with
multiple security vulnerabilities. It serves as the audit target
for the Secure Code Review task.

Vulnerabilities embedded (do NOT fix before running the audit):
  V-01: SQL Injection (login form)
  V-02: Stored XSS (comment submission)
  V-03: Hardcoded credentials & secret key
  V-04: Insecure password storage (MD5, no salt)
  V-05: Path Traversal (file download route)
  V-06: Broken Access Control (admin route, no auth check)
  V-07: IDOR (user profile fetch by raw user ID)
  V-08: Sensitive data exposure in error messages
  V-09: CSRF (no tokens on state-changing forms)
  V-10: Insecure session cookie (no HttpOnly / Secure flags)
"""

import hashlib
import os
import sqlite3

from flask import (Flask, g, redirect, render_template_string,
                   request, send_file, session, url_for)

# ── V-03: Hardcoded credentials and guessable secret key ─────────
app = Flask(__name__)
app.secret_key = "secret123"          # VULN: trivially guessable
ADMIN_PASSWORD = "admin"              # VULN: hardcoded admin password
DB_PATH = "/tmp/vuln_app.db"

# ─────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                role     TEXT DEFAULT 'user'
            );
            CREATE TABLE IF NOT EXISTS comments (
                id      INTEGER PRIMARY KEY,
                author  TEXT,
                content TEXT
            );
            INSERT OR IGNORE INTO users (username, password, role)
                VALUES ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin');
            INSERT OR IGNORE INTO users (username, password, role)
                VALUES ('alice', '6384e2b2184bcbf58eccf10ca7a6563c', 'user');
        """)
        db.commit()

# ─────────────────────────────────────────────────────────────────
# Templates (inline for simplicity)
# ─────────────────────────────────────────────────────────────────
BASE_HTML = """
<!DOCTYPE html><html><head>
<title>VulnBank Demo App</title>
<style>
  body{{font-family:monospace;background:#1a1a2e;color:#eee;padding:30px}}
  input,button{{padding:8px;margin:4px;border-radius:4px;border:1px solid #444}}
  button{{background:#4fc3f7;color:#000;cursor:pointer}}
  a{{color:#80deea}}
  .err{{color:#ef9a9a}} .ok{{color:#a5d6a7}}
  .box{{background:#16213e;padding:20px;border-radius:8px;max-width:600px;margin-bottom:20px}}
</style>
</head><body>
<h2>🏦 VulnBank — Demo Application</h2>
<p><a href="/">Home</a> | <a href="/login">Login</a> |
   <a href="/comments">Comments</a> | <a href="/admin">Admin</a></p>
<hr>
{content}
</body></html>
"""

# ─────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    user = session.get("username", "Guest")
    return render_template_string(BASE_HTML.format(
        content=f"<div class='box'><h3>Welcome, {user}!</h3>"
                "<p>This is a deliberately vulnerable demo app for security auditing.</p></div>"
    ))

# ── V-01: SQL Injection ───────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN V-01: Raw string interpolation → SQL Injection
        # ' OR '1'='1  bypasses authentication entirely
        pw_hash = hashlib.md5(password.encode()).hexdigest()  # V-04
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{pw_hash}'"
        )
        try:
            db = get_db()
            user = db.execute(query).fetchone()   # ← Vulnerable
            if user:
                session["username"] = user["username"]
                session["role"]     = user["role"]
                return redirect(url_for("index"))
            else:
                error = "Invalid credentials"
        except Exception as e:
            # V-08: Full exception details exposed to user
            error = f"Database error: {e} | Query was: {query}"

    form = """
    <div class='box'>
      <h3>Login</h3>
      <form method='post'>
        Username: <input name='username'><br>
        Password: <input name='password' type='password'><br>
        <button type='submit'>Login</button>
      </form>
      {err}
    </div>"""
    return render_template_string(BASE_HTML.format(
        content=form.format(err=f"<p class='err'>{error}</p>" if error else "")
    ))

# ── V-02: Stored XSS ─────────────────────────────────────────────
@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    if request.method == "POST":
        author  = request.form.get("author", "Anonymous")
        content = request.form.get("content", "")
        # VULN V-02: Content stored and rendered without sanitization
        db.execute("INSERT INTO comments (author,content) VALUES (?,?)",
                   (author, content))
        db.commit()

    rows = db.execute("SELECT * FROM comments").fetchall()
    # VULN V-02: Rendered with |safe — XSS payload executes in browser
    comment_html = "".join(
        f"<div class='box'><b>{r['author']}</b>: {r['content']}</div>"
        for r in rows
    )
    form = """
    <div class='box'>
      <h3>Leave a Comment</h3>
      <!-- V-09: No CSRF token on form -->
      <form method='post'>
        Name   : <input name='author'><br>
        Comment: <textarea name='content'></textarea><br>
        <button type='submit'>Post</button>
      </form>
    </div>
    """ + comment_html
    return render_template_string(BASE_HTML.format(content=form))

# ── V-05: Path Traversal ─────────────────────────────────────────
@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    # VULN V-05: No sanitization — ../../etc/passwd works
    filepath = os.path.join("/var/www/files", filename)
    try:
        return send_file(filepath)
    except Exception as e:
        # V-08: Leaks server path in error
        return f"Error reading file: {filepath} → {e}", 500

# ── V-06: Broken Access Control ──────────────────────────────────
@app.route("/admin")
def admin():
    # VULN V-06: No authentication check whatsoever
    db   = get_db()
    rows = db.execute("SELECT id,username,role FROM users").fetchall()
    table = "".join(
        f"<tr><td>{r['id']}</td><td>{r['username']}</td><td>{r['role']}</td></tr>"
        for r in rows
    )
    return render_template_string(BASE_HTML.format(
        content=f"<div class='box'><h3>Admin Panel</h3>"
                f"<table border='1'><tr><th>ID</th><th>User</th><th>Role</th></tr>"
                f"{table}</table></div>"
    ))

# ── V-07: IDOR (Insecure Direct Object Reference) ────────────────
@app.route("/user/<int:user_id>")
def user_profile(user_id):
    # VULN V-07: Any user can view any other user's profile by ID
    db  = get_db()
    row = db.execute("SELECT id,username,role FROM users WHERE id=?",
                     (user_id,)).fetchone()
    if row:
        return render_template_string(BASE_HTML.format(
            content=f"<div class='box'><h3>Profile</h3>"
                    f"<p>ID: {row['id']}<br>Username: {row['username']}<br>"
                    f"Role: {row['role']}</p></div>"
        ))
    return "User not found", 404

# ── V-10: Insecure cookie configuration ──────────────────────────
@app.after_request
def set_insecure_cookies(response):
    # VULN V-10: No HttpOnly, no Secure, no SameSite flags set
    # session cookie is accessible by JavaScript (allows XSS cookie theft)
    return response

# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    # V-03 continued: Debug mode ON in production → exposes interactive debugger
    app.run(debug=True, host="0.0.0.0", port=5000)
