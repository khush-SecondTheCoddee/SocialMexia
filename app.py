# app.py
"""
Mini Social — single-file production-ready Flask app

Key production notes:
 - Configure via environment variables (see defaults below).
 - Serve with a WSGI server (recommended): e.g.
     gunicorn -w 4 -b 0.0.0.0:5000 app:app
 - For static/uploads in production, prefer a reverse proxy (nginx) to serve
   files directly. This app can serve uploads for small demos.
"""

import os
import re
import sqlite3
import base64
import datetime
import functools
import uuid
import logging
from typing import Optional
from pathlib import Path

from flask import (
    Flask,
    request,
    jsonify,
    g,
    send_from_directory,
    render_template_string,
    abort,
)
import jwt  # PyJWT
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS

# -----------------------
# Configuration (env)
# -----------------------
BASE_DIR = Path(__file__).parent.resolve()
DATABASE = os.environ.get("SOCIAL_DATABASE", str(BASE_DIR / "social.db"))
UPLOAD_FOLDER = os.environ.get("SOCIAL_UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
JWT_SECRET = os.environ.get("SOCIAL_JWT_SECRET", None)
if not JWT_SECRET:
    # In production this MUST be set. For dev only fallback:
    JWT_SECRET = "please_set_SOCIAL_JWT_SECRET_in_env"
JWT_ALGORITHM = os.environ.get("SOCIAL_JWT_ALGORITHM", "HS256")
JWT_EXP_SECONDS = int(os.environ.get("SOCIAL_JWT_EXP_SECONDS", 60 * 60 * 24 * 7))  # default 7 days

MAX_CONTENT_LENGTH = int(os.environ.get("SOCIAL_MAX_CONTENT_LENGTH", 8 * 1024 * 1024))  # 8 MB by default
ALLOWED_EXTENSIONS = set(os.environ.get("SOCIAL_ALLOWED_EXT", "png,jpg,jpeg,gif,webp").split(","))
CORS_ORIGINS = os.environ.get("SOCIAL_CORS_ORIGINS", "*")  # set to origin(s) in prod

# Pagination limits
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100

# create folders
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -----------------------
# App init
# -----------------------
app = Flask(__name__, static_folder=None)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["DATABASE"] = DATABASE
app.config["SECRET_KEY"] = JWT_SECRET
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# CORS
CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}})

# Logging
logging.basicConfig(level=os.environ.get("SOCIAL_LOG_LEVEL", "INFO"))
logger = logging.getLogger("mini-social")

# -----------------------
# Database helpers
# -----------------------
def get_db():
    """
    Returns a sqlite3.Connection. We use check_same_thread=False to allow
    multi-worker WSGI servers (sqlite still has concurrency limits).
    We also set some pragmas for better performance/concurrency.
    """
    if "db" not in g:
        conn = sqlite3.connect(
            app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Performance / integrity pragmas suitable for many small requests
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()
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


# -----------------------
# JWT helpers
# -----------------------
def create_token(user_id: int):
    payload = {
        "sub": int(user_id),
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_SECONDS),
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm=JWT_ALGORITHM)
    # PyJWT may return bytes on some versions
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def jwt_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth.split(" ", 1)[1].strip()
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.current_user = get_user_by_id(payload["sub"])
        if not g.current_user:
            return jsonify({"error": "User not found"}), 401
        return f(*args, **kwargs)
    return wrapper


# -----------------------
# DB initialization
# -----------------------
def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript(
        """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT,
    image_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
);
"""
    )
    db.commit()
    cur.close()


# -----------------------
# Utility helpers
# -----------------------
def user_to_dict(row):
    if row is None:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "bio": row["bio"],
        "created_at": row["created_at"],
    }


def get_user_by_id(user_id: int):
    r = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    return user_to_dict(r)


def get_user_by_username(username: str):
    r = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
    return user_to_dict(r)


# upload helpers
def allowed_file_extension(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def is_image_mimetype(file_storage) -> bool:
    # some clients set wrong mimetype; we do a defensive check
    mimetype = (file_storage.mimetype or "").lower()
    return mimetype.startswith("image/")


def save_image_file(file_storage=None, image_base64=None):
    """
    Accepts either a Werkzeug FileStorage or a base64 data URL.
    Returns filename (relative to UPLOAD_FOLDER) or None on error.
    """
    if file_storage:
        filename = secure_filename(file_storage.filename) if file_storage.filename else ""
        if not filename:
            return None
        if not allowed_file_extension(filename) or not is_image_mimetype(file_storage):
            return None
        name = f"{uuid.uuid4().hex}_{filename}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], name)
        # IMPORTANT: limit size is already enforced by Flask MAX_CONTENT_LENGTH
        file_storage.save(path)
        return name

    if image_base64:
        if "," in image_base64:
            _, b64 = image_base64.split(",", 1)
        else:
            b64 = image_base64
        try:
            data = base64.b64decode(b64)
        except Exception:
            return None
        # try to be smart about extension detection (very limited)
        # default to .bin if detection fails
        ext = "bin"
        # very simple magic bytes sniff
        if data[:3] == b"\xff\xd8\xff":
            ext = "jpg"
        elif data[:8].startswith(b"\x89PNG"):
            ext = "png"
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            ext = "gif"
        elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            ext = "webp"

        if ext not in ALLOWED_EXTENSIONS:
            return None

        name = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], name)
        with open(path, "wb") as f:
            f.write(data)
        return name
    return None


def post_to_dict(row, viewer_id=None):
    if row is None:
        return None
    post_id = row["id"]
    likes_row = query_db("SELECT COUNT(*) as c FROM likes WHERE post_id = ?", (post_id,), one=True)
    likes_count = likes_row["c"] if likes_row else 0
    comments_row = query_db("SELECT COUNT(*) as c FROM comments WHERE post_id = ?", (post_id,), one=True)
    comments_count = comments_row["c"] if comments_row else 0
    liked = False
    if viewer_id:
        r = query_db("SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?", (post_id, viewer_id), one=True)
        liked = bool(r)
    user = get_user_by_id(row["user_id"])
    return {
        "id": post_id,
        "user": {"id": user["id"], "username": user["username"]} if user else None,
        "content": row["content"],
        "image_url": f"/uploads/{row['image_path']}" if row["image_path"] else None,
        "created_at": row["created_at"],
        "likes_count": likes_count,
        "comments_count": comments_count,
        "liked_by_me": liked,
    }


# -----------------------
# Validation helpers
# -----------------------
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def validate_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


# -----------------------
# Routes
# -----------------------

@app.route("/init", methods=["POST", "GET"])
def route_init():
    """
    Initialize DB. For production, only call this during deployment or migration.
    """
    init_db()
    return jsonify({"status": "ok", "msg": "Database initialized"})


@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email and password required"}), 400

    if not validate_email(email):
        return jsonify({"error": "invalid email"}), 400

    if query_db("SELECT id FROM users WHERE username = ? OR email = ?", (username, email), one=True):
        return jsonify({"error": "username or email already exists"}), 400

    password_hash = generate_password_hash(password)
    user_id = execute_db(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash),
    )
    user = get_user_by_id(user_id)
    token = create_token(user_id)
    return jsonify({"user": user, "token": token})


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    identifier = (data.get("username") or data.get("email") or "").strip()
    password = data.get("password") or ""
    if not identifier or not password:
        return jsonify({"error": "username/email and password required"}), 400

    row = query_db("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier), one=True)
    if not row:
        return jsonify({"error": "Invalid credentials"}), 401
    if not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(row["id"])
    return jsonify({"user": user_to_dict(row), "token": token})


@app.route("/me", methods=["GET"])
@jwt_required
def me():
    return jsonify({"user": g.current_user})


@app.route("/me", methods=["PUT"])
@jwt_required
def update_profile():
    data = request.json or {}
    bio = (data.get("bio") or "").strip()
    execute_db("UPDATE users SET bio = ? WHERE id = ?", (bio, g.current_user["id"]))
    user = get_user_by_id(g.current_user["id"])
    return jsonify({"user": user})


@app.route("/users/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    followers = query_db("SELECT COUNT(*) as c FROM follows WHERE following_id = ?", (user_id,), one=True)["c"]
    following = query_db("SELECT COUNT(*) as c FROM follows WHERE follower_id = ?", (user_id,), one=True)["c"]
    return jsonify({"user": user, "followers": followers, "following": following})


@app.route("/users/search", methods=["GET"])
def search_users():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results": []})
    qlike = f"%{q}%"
    rows = query_db("SELECT id, username, bio FROM users WHERE username LIKE ? OR email LIKE ? LIMIT 30", (qlike, qlike))
    results = [{"id": r["id"], "username": r["username"], "bio": r["bio"]} for r in rows]
    return jsonify({"results": results})


@app.route("/follow/<int:target_id>", methods=["POST"])
@jwt_required
def follow(target_id):
    if target_id == g.current_user["id"]:
        return jsonify({"error": "Cannot follow yourself"}), 400
    exists = query_db("SELECT 1 FROM users WHERE id = ?", (target_id,), one=True)
    if not exists:
        return jsonify({"error": "Target user not found"}), 404
    rel = query_db("SELECT id FROM follows WHERE follower_id = ? AND following_id = ?", (g.current_user["id"], target_id), one=True)
    if rel:
        execute_db("DELETE FROM follows WHERE id = ?", (rel["id"],))
        return jsonify({"status": "unfollowed"})
    else:
        execute_db("INSERT INTO follows (follower_id, following_id) VALUES (?, ?)", (g.current_user["id"], target_id))
        return jsonify({"status": "followed"})


@app.route("/posts", methods=["POST"])
@jwt_required
def create_post():
    # multipart/form-data or JSON accepted
    content = None
    image_path = None
    if request.is_json:
        data = request.json or {}
        content = data.get("content", "")
        image_b64 = data.get("image_base64")
        image_path = save_image_file(image_base64=image_b64) if image_b64 else None
        if image_b64 and image_path is None:
            return jsonify({"error": "Invalid base64 image or unsupported format"}), 400
    else:
        content = (request.form.get("content") or "")
        file = request.files.get("image")
        if file:
            saved = save_image_file(file_storage=file)
            if not saved:
                return jsonify({"error": "Invalid image upload (type/extension) or too large"}), 400
            image_path = saved

    post_id = execute_db(
        "INSERT INTO posts (user_id, content, image_path) VALUES (?, ?, ?)",
        (g.current_user["id"], content, image_path),
    )
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    return jsonify({"post": post_to_dict(row, viewer_id=g.current_user["id"])}), 201


@app.route("/uploads/<path:filename>", methods=["GET"])
def uploaded_file(filename):
    # Serve uploaded files (insecure for high-scale production — use nginx or S3)
    safe_path = os.path.normpath(filename)
    if safe_path.startswith(".."):
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)


@app.route("/posts/<int:post_id>", methods=["GET"])
def get_post(post_id):
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    if not row:
        return jsonify({"error": "Post not found"}), 404
    viewer = getattr(g, "current_user", None)
    viewer_id = viewer["id"] if viewer else None
    return jsonify({"post": post_to_dict(row, viewer_id=viewer_id)})


@app.route("/posts/<int:post_id>/like", methods=["POST"])
@jwt_required
def like_post(post_id):
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    if not row:
        return jsonify({"error": "Post not found"}), 404
    existing = query_db("SELECT id FROM likes WHERE user_id = ? AND post_id = ?", (g.current_user["id"], post_id), one=True)
    if existing:
        execute_db("DELETE FROM likes WHERE id = ?", (existing["id"],))
        return jsonify({"status": "unliked"})
    else:
        execute_db("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", (g.current_user["id"], post_id))
        return jsonify({"status": "liked"})


@app.route("/posts/<int:post_id>/comments", methods=["GET"])
def comments_get(post_id):
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    if not row:
        return jsonify({"error": "Post not found"}), 404

    rows = query_db(
        "SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE post_id = ? ORDER BY created_at ASC",
        (post_id,),
    )
    data = [
        {"id": r["id"], "user": {"id": r["user_id"], "username": r["username"]}, "content": r["content"], "created_at": r["created_at"]}
        for r in rows
    ]
    return jsonify({"comments": data})


@app.route("/posts/<int:post_id>/comments", methods=["POST"])
@jwt_required
def comments_post(post_id):
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    if not row:
        return jsonify({"error": "Post not found"}), 404
    data = request.json or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "content required"}), 400
    comment_id = execute_db("INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)", (g.current_user["id"], post_id, content))
    row = query_db("SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?", (comment_id,), one=True)
    return jsonify({"comment": {"id": row["id"], "user": {"id": row["user_id"], "username": row["username"]}, "content": row["content"], "created_at": row["created_at"]}}), 201


@app.route("/feed", methods=["GET"])
@jwt_required
def feed():
    # Simple feed: posts by the user and users they follow, paginated
    try:
        limit = int(request.args.get("limit", DEFAULT_PAGE_LIMIT))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        return jsonify({"error": f"limit must be between 1 and {MAX_PAGE_LIMIT}"}), 400

    rows = query_db(
        """
        SELECT p.* FROM posts p
        WHERE p.user_id = ?
           OR p.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?)
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (g.current_user["id"], g.current_user["id"], limit, offset),
    )
    posts = [post_to_dict(r, viewer_id=g.current_user["id"]) for r in rows]
    return jsonify({"posts": posts})


@app.route("/users/<int:user_id>/posts", methods=["GET"])
def user_posts(user_id):
    try:
        limit = int(request.args.get("limit", DEFAULT_PAGE_LIMIT))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        return jsonify({"error": f"limit must be between 1 and {MAX_PAGE_LIMIT}"}), 400

    rows = query_db("SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", (user_id, limit, offset))
    viewer = getattr(g, "current_user", None)
    viewer_id = viewer["id"] if viewer else None
    return jsonify({"posts": [post_to_dict(r, viewer_id=viewer_id) for r in rows]})


@app.route("/followings", methods=["GET"])
@jwt_required
def followings():
    rows = query_db(
        "SELECT u.id, u.username FROM follows f JOIN users u ON f.following_id = u.id WHERE f.follower_id = ?",
        (g.current_user["id"],),
    )
    res = [{"id": r["id"], "username": r["username"]} for r in rows]
    return jsonify({"followings": res})


@app.route("/followers", methods=["GET"])
@jwt_required
def followers():
    rows = query_db(
        "SELECT u.id, u.username FROM follows f JOIN users u ON f.follower_id = u.id WHERE f.following_id = ?",
        (g.current_user["id"],),
    )
    res = [{"id": r["id"], "username": r["username"]} for r in rows]
    return jsonify({"followers": res})


@app.route("/search_posts", methods=["GET"])
def search_posts():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results": []})
    qlike = f"%{q}%"
    rows = query_db("SELECT * FROM posts WHERE content LIKE ? ORDER BY created_at DESC LIMIT 50", (qlike,))
    viewer = getattr(g, "current_user", None)
    viewer_id = viewer["id"] if viewer else None
    return jsonify({"results": [post_to_dict(r, viewer_id=viewer_id) for r in rows]})


# -----------------------
# Embedded simple HTML UI served at /
# (kept mostly same as original demo; still safe since content is escaped client-side)
# -----------------------
INDEX_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Mini Social (demo)</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    body { font-family: Arial, sans-serif; max-width:900px; margin: 20px auto; }
    .col { display:flex; gap:20px; flex-wrap:wrap; }
    .card { border: 1px solid #ddd; padding:12px; border-radius:6px; margin-bottom:12px; box-shadow: 0 1px 3px rgba(0,0,0,0.03); }
    .post img { max-width:100%; height:auto; border-radius:6px; margin-top:8px; }
    .small { font-size:0.9em; color:#666; }
    button { cursor:pointer; padding:6px 10px; border-radius:6px; border:1px solid #ddd; background:#fff; }
    textarea { width:100%; min-height:60px; padding:6px; border-radius:6px; border:1px solid #ccc; }
    input[type="text"], input[type="email"], input[type="password"] { width:100%; padding:6px; border-radius:6px; border:1px solid #ccc; }
  </style>
</head>
<body>
  <h1>Mini Social — Demo UI</h1>

  <div id="auth" class="card">
    <div id="user-info"></div>

    <div id="not-logged">
      <h3>Register</h3>
      <input id="reg-username" placeholder="username" /><br/>
      <input id="reg-email" placeholder="email" /><br/>
      <input id="reg-password" type="password" placeholder="password" /><br/>
      <button onclick="register()">Register</button>

      <hr/>
      <h3>Login</h3>
      <input id="login-identifier" placeholder="username or email" /><br/>
      <input id="login-password" type="password" placeholder="password" /><br/>
      <button onclick="login()">Login</button>
    </div>

    <div id="logged" style="display:none;">
      <div>
        Logged in as <strong id="me-username"></strong>
        <button onclick="logout()">Logout</button>
      </div>
      <div class="small">Token: <span id="token-display" style="word-break:break-all;"></span></div>
    </div>
  </div>

  <div class="col">
    <div style="flex:2; min-width:320px;">
      <div class="card">
        <h3>Create Post</h3>
        <textarea id="post-content" placeholder="Write something..."></textarea><br/>
        <input type="file" id="post-image" accept="image/*" /><br/>
        <button onclick="createPost()">Post</button>
      </div>

      <div class="card">
        <h3>Feed</h3>
        <div id="feed"></div>
        <button onclick="loadFeed()">Refresh Feed</button>
      </div>
    </div>

    <div style="flex:1; min-width:220px;">
      <div class="card">
        <h3>Search Users</h3>
        <input id="search-q" placeholder="username or email" />
        <button onclick="searchUsers()">Search</button>
        <div id="search-results"></div>
      </div>
      <div class="card">
        <h3>My Followings</h3>
        <div id="my-followings"></div>
      </div>
    </div>
  </div>

<script>
const api = (path, opts) => fetch(path, opts);
function setLogged(token, user){
  if(!token) { localStorage.removeItem('token'); document.getElementById('not-logged').style.display='block'; document.getElementById('logged').style.display='none'; document.getElementById('user-info').innerText=''; return; }
  localStorage.setItem('token', token);
  document.getElementById('not-logged').style.display='none';
  document.getElementById('logged').style.display='block';
  document.getElementById('me-username').innerText = user.username;
  document.getElementById('token-display').innerText = token;
  document.getElementById('user-info').innerText = '';
  loadFeed();
  loadFollowings();
}
function getToken(){ return localStorage.getItem('token') || ''; }

async function register(){
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const res = await api('/register', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username,email,password})
  });
  const j = await res.json();
  if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
  setLogged(j.token, j.user);
}

async function login(){
  const identifier = document.getElementById('login-identifier').value;
  const password = document.getElementById('login-password').value;
  const res = await api('/login', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username: identifier, password})
  });
  const j = await res.json();
  if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
  setLogged(j.token, j.user);
}

function logout(){ setLogged(null); }

async function createPost(){
  const token = getToken();
  const content = document.getElementById('post-content').value;
  const file = document.getElementById('post-image').files[0];
  if(file){
    const fd = new FormData();
    fd.append('content', content);
    fd.append('image', file);
    const res = await fetch('/posts', { method:'POST', body: fd, headers: token ? {'Authorization':'Bearer ' + token} : {} });
    const j = await res.json();
    if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
    document.getElementById('post-content').value='';
    document.getElementById('post-image').value='';
    loadFeed();
  } else {
    const res = await api('/posts', { method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer ' + token }, body: JSON.stringify({content}) });
    const j = await res.json();
    if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
    document.getElementById('post-content').value='';
    loadFeed();
  }
}

function buildPostHtml(p){
  const imgHtml = p.image_url ? `<div><img src="${p.image_url}" /></div>` : '';
  const likeBtn = `<button onclick="toggleLike(${p.id})">${p.liked_by_me ? 'Unlike' : 'Like'} (${p.likes_count})</button>`;
  const commentBtn = `<button onclick="showComments(${p.id})">Comments (${p.comments_count})</button>`;
  return `<div class="card post"><div><strong>@${p.user.username}</strong> <span class="small">${p.created_at}</span></div><div>${escapeHtml(p.content || '')}</div>${imgHtml}<div class="small">${likeBtn} ${commentBtn}</div><div id="comments-${p.id}"></div></div>`;
}

function escapeHtml(unsafe) {
    if(!unsafe) return '';
    return unsafe
         .replaceAll('&', '&amp;')
         .replaceAll('<', '&lt;')
         .replaceAll('>', '&gt;')
         .replaceAll('"', '&quot;')
         .replaceAll("'", '&#039;');
}

async function loadFeed(){
  const token = getToken();
  const res = await api('/feed', { headers: token ? {'Authorization':'Bearer ' + token} : {} });
  if(res.status === 401){ setLogged(null); return; }
  const j = await res.json();
  const feed = document.getElementById('feed');
  feed.innerHTML = '';
  if(!j.posts) return;
  j.posts.forEach(p => feed.insertAdjacentHTML('beforeend', buildPostHtml(p)));
}

async function toggleLike(postId){
  const token = getToken();
  const res = await api(`/posts/${postId}/like`, { method:'POST', headers: {'Authorization':'Bearer ' + token} });
  const j = await res.json();
  if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
  loadFeed();
}

async function showComments(postId){
  const res = await api(`/posts/${postId}/comments`);
  const j = await res.json();
  const container = document.getElementById(`comments-${postId}`);
  container.innerHTML = '';
  if(j.comments){
    j.comments.forEach(c => {
      container.insertAdjacentHTML('beforeend', `<div class="small"><strong>@${c.user.username}</strong>: ${escapeHtml(c.content)}</div>`);
    });
  }
  container.insertAdjacentHTML('beforeend', `<div><input id="comment-input-${postId}" placeholder="Write comment..." /> <button onclick="postComment(${postId})">Send</button></div>`);
}

async function postComment(postId){
  const token = getToken();
  if(!token){ alert('Login to comment'); return; }
  const content = document.getElementById(`comment-input-${postId}`).value;
  const res = await api(`/posts/${postId}/comments`, { method:'POST', headers:{'Content-Type':'application/json', 'Authorization':'Bearer ' + token}, body: JSON.stringify({content}) });
  const j = await res.json();
  if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
  showComments(postId);
}

async function searchUsers(){
  const q = document.getElementById('search-q').value;
  const res = await api(`/users/search?q=${encodeURIComponent(q)}`);
  const j = await res.json();
  const out = document.getElementById('search-results');
  out.innerHTML = '';
  (j.results || []).forEach(u => {
    out.insertAdjacentHTML('beforeend', `<div>${u.username} <button onclick="follow(${u.id})">Follow/Unfollow</button></div>`);
  });
}

async function follow(userId){
  const token = getToken();
  const res = await api(`/follow/${userId}`, { method:'POST', headers: {'Authorization':'Bearer ' + token} });
  const j = await res.json();
  if(!res.ok){ alert(j.error || JSON.stringify(j)); return; }
  loadFollowings();
  loadFeed();
}

async function loadFollowings(){
  const token = getToken();
  const res = await api('/followings', { headers: token ? {'Authorization':'Bearer ' + token} : {} });
  const j = await res.json();
  const out = document.getElementById('my-followings');
  out.innerHTML = '';
  if(j.followings) j.followings.forEach(u => out.insertAdjacentHTML('beforeend', `<div>@${u.username}</div>`));
}

// restore session if token exists
(async ()=> {
  const token = getToken();
  if(!token) return;
  // try to get /me
  const res = await api('/me', { headers: {'Authorization':'Bearer ' + token} });
  if(res.ok){
    const j = await res.json();
    setLogged(token, j.user);
  } else {
    setLogged(null);
  }
})();
</script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index_ui():
    return render_template_string(INDEX_HTML)


# -----------------------
# Security headers
# -----------------------
@app.after_request
def set_security_headers(response):
    # Basic security headers; tune for your deployment
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
    # Content Security Policy: this is permissive for demo UI. Lock down in production.
    response.headers.setdefault("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:; img-src 'self' data:;")
    # HSTS - only enable if serving HTTPS
    # response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# -----------------------
# Error handlers
# -----------------------
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Uploaded file is too large"}), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400


# -----------------------
# Startup: initialize DB on first run
# -----------------------
with app.app_context():
    init_db()
    logger.info("Database initialized/ready at %s", app.config["DATABASE"])
    logger.info("Uploads folder: %s", app.config["UPLOAD_FOLDER"])

# -----------------------
# Run server (for dev only). For production use a WSGI server.
# -----------------------
if __name__ == "__main__":
    # dev server
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG", "0") == "1")
