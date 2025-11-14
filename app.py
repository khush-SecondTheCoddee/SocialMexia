import os
import sqlite3
import base64
import datetime
import functools
import uuid
from typing import Optional

from flask import Flask, request, jsonify, g, send_from_directory
import jwt  # PyJWT
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

# Configuration
DATABASE = "social.db"
UPLOAD_FOLDER = "uploads"
JWT_SECRET = os.environ.get("SOCIAL_JWT_SECRET", "change_this_secret_in_env")
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 60 * 60 * 24 * 7  # 7 days

# App init
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["DATABASE"] = DATABASE
app.config["SECRET_KEY"] = JWT_SECRET
CORS(app)

# Ensure uploads folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Database helpers
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES)
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


# JWT helpers
def create_token(user_id: int):
    payload = {
        "sub": user_id,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_SECONDS),
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm=JWT_ALGORITHM)
    # PyJWT may return bytes in older versions; ensure str
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


# DB initialization
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


# Utility helpers
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


def save_image_file(file_storage=None, image_base64=None):
    if file_storage:
        filename = f"{uuid.uuid4().hex}_{file_storage.filename}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file_storage.save(path)
        return filename
    if image_base64:
        # Expect data like "data:image/png;base64,AAAA..."
        if "," in image_base64:
            _, b64 = image_base64.split(",", 1)
        else:
            b64 = image_base64
        try:
            data = base64.b64decode(b64)
        except Exception:
            return None
        filename = f"{uuid.uuid4().hex}.bin"
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        with open(path, "wb") as f:
            f.write(data)
        return filename
    return None


def post_to_dict(row, viewer_id=None):
    if row is None:
        return None
    post_id = row["id"]
    # counts
    likes_count = query_db("SELECT COUNT(*) as c FROM likes WHERE post_id = ?", (post_id,), one=True)["c"]
    comments_count = query_db("SELECT COUNT(*) as c FROM comments WHERE post_id = ?", (post_id,), one=True)["c"]
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


# Routes

@app.route("/init", methods=["POST", "GET"])
def route_init():
    """
    Initialize DB. Called automatically at startup, but exposed if you want to re-create.
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
    username_or_email = (data.get("username") or data.get("email") or "").strip()
    password = data.get("password") or ""
    if not username_or_email or not password:
        return jsonify({"error": "username/email and password required"}), 400

    row = query_db("SELECT * FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email), one=True)
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
    bio = data.get("bio", "").strip()
    execute_db("UPDATE users SET bio = ? WHERE id = ?", (bio, g.current_user["id"]))
    user = get_user_by_id(g.current_user["id"])
    return jsonify({"user": user})


@app.route("/users/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    # follower / following counts
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
    # toggle follow/unfollow
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
    else:
        content = (request.form.get("content") or "")
        file = request.files.get("image")
        image_path = save_image_file(file_storage=file) if file else None

    post_id = execute_db(
        "INSERT INTO posts (user_id, content, image_path) VALUES (?, ?, ?)",
        (g.current_user["id"], content, image_path),
    )
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    return jsonify({"post": post_to_dict(row, viewer_id=g.current_user["id"])}), 201


@app.route("/uploads/<path:filename>", methods=["GET"])
def uploaded_file(filename):
    # Serve uploaded files (insecure for production — use proper static file serving)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


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


@app.route("/posts/<int:post_id>/comments", methods=["GET", "POST"])
def comments_route(post_id):
    row = query_db("SELECT * FROM posts WHERE id = ?", (post_id,), one=True)
    if not row:
        return jsonify({"error": "Post not found"}), 404

    if request.method == "GET":
        rows = query_db(
            "SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE post_id = ? ORDER BY created_at ASC",
            (post_id,),
        )
        data = [
            {"id": r["id"], "user": {"id": r["user_id"], "username": r["username"]}, "content": r["content"], "created_at": r["created_at"]}
            for r in rows
        ]
        return jsonify({"comments": data})

    # POST (create)
    # require auth
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth.split(" ", 1)[1].strip()
    payload = decode_token(token)
    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 401
    user = get_user_by_id(payload["sub"])
    if not user:
        return jsonify({"error": "User not found"}), 401
    data = request.json or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "content required"}), 400
    comment_id = execute_db("INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)", (user["id"], post_id, content))
    row = query_db("SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?", (comment_id,), one=True)
    return jsonify({"comment": {"id": row["id"], "user": {"id": row["user_id"], "username": row["username"]}, "content": row["content"], "created_at": row["created_at"]}}), 201


@app.route("/feed", methods=["GET"])
@jwt_required
def feed():
    # Simple feed: posts by the user and users they follow, paginated
    limit = int(request.args.get("limit", 20))
    offset = int(request.args.get("offset", 0))
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
    limit = int(request.args.get("limit", 20))
    offset = int(request.args.get("offset", 0))
    rows = query_db("SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", (user_id, limit, offset))
    viewer = getattr(g, "current_user", None)
    viewer_id = viewer["id"] if viewer else None
    return jsonify({"posts": [post_to_dict(r, viewer_id=viewer_id) for r in rows]})


@app.route("/followings", methods=["GET"])
@jwt_required
def followings():
    # list of users current user follows
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


# Initialize DB at startup
with app.app_context():
    init_db()


# Run server
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
