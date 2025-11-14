# Full Production-Ready Single-File Flask App with JWT Cookie Auth
# Admin account auto-created:
#   username: admin
#   email: admin@example.com
#   password: Admin@123

import os
import sqlite3
import base64
import datetime
import functools
import uuid
from typing import Optional

from flask import Flask, request, jsonify, g, send_from_directory, render_template_string, make_response, redirect
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from markupsafe import Markup

# -------------------------------
# Config
# -------------------------------
DATABASE = "social.db"
UPLOAD_FOLDER = "uploads"
JWT_SECRET = os.environ.get("SOCIAL_JWT_SECRET", "change_this_secret_in_env")
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 60 * 60 * 24 * 7  # 7 days

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["DATABASE"] = DATABASE
app.config["SECRET_KEY"] = JWT_SECRET
CORS(app)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------------------
# DB Helpers
# -------------------------------
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    conn = get_db()
    cur = conn.execute(query, args)
    conn.commit()
    lastrowid = cur.lastrowid
    cur.close()
    return lastrowid

# -------------------------------
# JWT Helpers
# -------------------------------
def create_token(user_id: int):
    payload = {
        "sub": user_id,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_SECONDS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


def jwt_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
        elif request.cookies.get("token"):
            token = request.cookies.get("token")

        if not token:
            return jsonify({"error": "Missing token"}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.current_user = get_user_by_id(payload["sub"])
        if not g.current_user:
            return jsonify({"error": "User not found"}), 401

        return f(*args, **kwargs)
    return wrapper

# -------------------------------
# Init DB and Admin
# -------------------------------
def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript('''
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        bio TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT,
        image_path TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER NOT NULL,
        following_id INTEGER NOT NULL,
        UNIQUE(follower_id, following_id),
        FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );
    ''')
    db.commit()
    cur.close()

    # Auto-create admin
    admin = query_db("SELECT * FROM users WHERE username = 'admin'", one=True)
    if not admin:
        execute_db(
            "INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?)",
            ("admin", "admin@example.com", generate_password_hash("Admin@123"))
        )

# -------------------------------
# Utils
# -------------------------------
def get_user_by_id(uid):
    r = query_db("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not r:
        return None
    return {"id": r["id"], "username": r["username"], "email": r["email"], "bio": r["bio"], "created_at": r["created_at"]}


def save_image_file(file_storage=None, image_base64=None):
    if file_storage:
        fname = f"{uuid.uuid4().hex}_{secure_filename(file_storage.filename)}"
        file_storage.save(os.path.join(UPLOAD_FOLDER, fname))
        return fname
    if image_base64:
        if "," in image_base64:
            _, b64 = image_base64.split(",", 1)
        else:
            b64 = image_base64
        data = base64.b64decode(b64)
        fname = f"{uuid.uuid4().hex}.bin"
        with open(os.path.join(UPLOAD_FOLDER, fname), "wb") as f:
            f.write(data)
        return fname
    return None

# -------------------------------
# Template Base
# -------------------------------
TEMPLATE_BASE = '''
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{{ title }}</title>
<style>
body{background:#0d0d0d;color:white;font-family:Inter,sans-serif;margin:0;}
.nav{padding:20px;background:#111;font-size:20px;text-align:center;border-bottom:1px solid #333;}
.card{margin:40px auto;background:#1a1a1a;max-width:450px;padding:30px;border-radius:18px;box-shadow:0 0 30px #0005;}
.input{width:100%;padding:12px;margin-top:10px;border-radius:10px;border:none;background:#222;color:white;}
.btn{margin-top:15px;width:100%;padding:14px;background:#4f46e5;border:none;border-radius:10px;font-size:16px;color:white;}
.link{color:#818cf8;text-decoration:none;}
</style>
</head>
<body>
<div class="nav">🔥 Cozy Premium Social</div>
<div class="card">{{ body|safe }}</div>
</body>
</html>
'''

# -------------------------------
# Pages
# -------------------------------
@app.route("/")
def page_index():
    body = """
<h2>Welcome</h2>
<p>Cozy premium social experience.</p>
<a class='link' href='/sign-up'>Sign Up</a><br>
<a class='link' href='/login'>Login</a>
"""
    return render_template_string(TEMPLATE_BASE, title="Welcome", body=Markup(body))

@app.route("/sign-up")
def page_signup():
    body = '''
<h2>Create Account</h2>
<form method='POST' action='/api/signup'>
<input class='input' name='username' placeholder='Username'>
<input class='input' name='email' placeholder='Email'>
<input class='input' name='password' placeholder='Password' type='password'>
<button class='btn'>Sign Up</button>
</form>
'''
    return render_template_string(TEMPLATE_BASE, title="Sign Up", body=Markup(body))

@app.route("/login")
def page_login():
    body = '''
<h2>Login</h2>
<form method='POST' action='/api/login'>
<input class='input' name='email' placeholder='Email'>
<input class='input' name='password' placeholder='Password' type='password'>
<button class='btn'>Login</button>
</form>
'''
    return render_template_string(TEMPLATE_BASE, title="Login", body=Markup(body))

@app.route("/home")
@jwt_required
def page_home():
    posts = query_db("SELECT * FROM posts ORDER BY created_at DESC LIMIT 20")
    posts_html = ""
    for p in posts:
        posts_html += f"<div><strong>User {p['user_id']}</strong>: {p['content']}</div><hr>"
    return render_template_string(TEMPLATE_BASE, title="Home", body=Markup(posts_html))

# -------------------------------
# API
# -------------------------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    username = request.form.get("username") or (request.json and request.json.get("username"))
    email = request.form.get("email") or (request.json and request.json.get("email"))
    password = request.form.get("password") or (request.json and request.json.get("password"))

    if not username or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    try:
        execute_db("INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?)",
                   (username, email, generate_password_hash(password)))
    except:
        return jsonify({"error": "Username or email already exists"}), 400

    row = query_db("SELECT * FROM users WHERE email=?", (email,), one=True)
    token = create_token(row['id'])
    resp = make_response(jsonify({"status": "ok", "message": "User created"}))
    resp.set_cookie("token", token, httponly=True, samesite="Lax", secure=False)
    return resp

@app.route("/api/login", methods=["POST"])
def api_login():
    email = request.form.get("email") or (request.json and request.json.get("email"))
    password = request.form.get("password") or (request.json and request.json.get("password"))

    row = query_db("SELECT * FROM users WHERE email=?", (email,), one=True)
    if not row or not check_password_hash(row['password_hash'], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(row['id'])
    resp = make_response(jsonify({"status": "ok"}))
    resp.set_cookie("token", token, httponly=True, samesite="Lax", secure=False)
    return resp

@app.route("/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"status": "ok"}))
    resp.delete_cookie("token")
    return resp

# -------------------------------
# File Serve
# -------------------------------
@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------------------
# Start
# -------------------------------
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8000)
