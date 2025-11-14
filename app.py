# app.py — Premium Educational Single-File Social App
#
# Features included (educational):
# - Hashed passwords (werkzeug)
# - Access + Refresh tokens (JWT)
# - Likes, comments, follows, notifications (simple)
# - Messages (basic DM storage)
# - Avatars (upload + simple resizing)
# - Feed, explore, user posts, profile, settings
# - Admin panel (basic)
# - Image optimization with Pillow
# - Pagination, rate limiting (simple per-IP), compression
# - Cozy & premium single-file UI (embedded HTML/CSS/JS)
#
# SECURITY NOTE (VERY IMPORTANT):
# This file was generated per user's request *for educational purposes only*.
# The user specifically requested that XSS prevention NOT be implemented. That
# decision is unsafe for production — DO NOT deploy this exact file to the
# public internet without implementing XSS and other protections.
#
# Run with: pip install -r requirements.txt
# Requirements: flask pyjwt flask-cors pillow werkzeug flask-compress
# Production: run with gunicorn (e.g., `gunicorn -w 4 -b 0.0.0.0:8000 app:app`)

import os
import io
import re
import sqlite3
import base64
import datetime
import uuid
import hashlib
import functools
from pathlib import Path
from typing import Optional
from PIL import Image

from flask import (
    Flask, request, jsonify, g, send_from_directory, render_template_string, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_compress import Compress
import jwt

# ----------------------------
# Config
# ----------------------------
BASE_DIR = Path(__file__).parent.resolve()
DATABASE = os.environ.get('SOCIAL_DATABASE', str(BASE_DIR / 'social.db'))
UPLOAD_FOLDER = os.environ.get('SOCIAL_UPLOAD_FOLDER', str(BASE_DIR / 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

JWT_ACCESS_SECRET = os.environ.get('SOCIAL_JWT_ACCESS', 'dev_access_secret_change')
JWT_REFRESH_SECRET = os.environ.get('SOCIAL_JWT_REFRESH', 'dev_refresh_secret_change')
JWT_ALGO = 'HS256'
ACCESS_EXPIRE_MIN = int(os.environ.get('SOCIAL_ACCESS_MIN', '30'))
REFRESH_EXPIRE_DAYS = int(os.environ.get('SOCIAL_REFRESH_DAYS', '7'))
MAX_UPLOAD_MB = int(os.environ.get('SOCIAL_MAX_UPLOAD_MB', '8'))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
ALLOWED_EXT = {'png','jpg','jpeg','gif','webp'}

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_BYTES
CORS(app)
Compress(app)

# ----------------------------
# DB helpers
# ----------------------------

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        # set pragmas
        cur = conn.cursor()
        cur.execute('PRAGMA journal_mode=WAL;')
        cur.execute('PRAGMA foreign_keys = ON;')
        cur.close()
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        bio TEXT DEFAULT '',
        avatar_path TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        content TEXT,
        image_path TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS follows (
        id TEXT PRIMARY KEY,
        follower_id TEXT NOT NULL,
        following_id TEXT NOT NULL,
        UNIQUE(follower_id, following_id),
        FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS likes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        post_id TEXT NOT NULL,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        post_id TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        sender_id TEXT NOT NULL,
        receiver_id TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        payload TEXT,
        read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    db.commit()
    cur.close()

with app.app_context():
    init_db()

# ----------------------------
# Utils
# ----------------------------

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


def make_id():
    return uuid.uuid4().hex

# JWT helpers

def create_access_token(user_id: str):
    now = datetime.datetime.utcnow()
    payload = {'sub': user_id, 'iat': now, 'exp': now + datetime.timedelta(minutes=ACCESS_EXPIRE_MIN)}
    token = jwt.encode(payload, JWT_ACCESS_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes): token = token.decode('utf-8')
    return token


def create_refresh_token(user_id: str):
    now = datetime.datetime.utcnow()
    payload = {'sub': user_id, 'iat': now, 'exp': now + datetime.timedelta(days=REFRESH_EXPIRE_DAYS)}
    token = jwt.encode(payload, JWT_REFRESH_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes): token = token.decode('utf-8')
    return token


def decode_access(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_ACCESS_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None


def decode_refresh(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_REFRESH_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None

# auth decorator

def jwt_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization','')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        token = auth.split(' ',1)[1].strip()
        payload = decode_access(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        g.current_user = get_user_by_id(payload['sub'])
        if not g.current_user:
            return jsonify({'error': 'User not found'}), 401
        return f(*args, **kwargs)
    return wrapper

# ----------------------------
# Image helpers (Pillow)
# ----------------------------

def allowed_filename(filename: str) -> bool:
    if '.' not in filename: return False
    return filename.rsplit('.',1)[1].lower() in ALLOWED_EXT


def save_and_optimize_image(file_storage, prefix='img', max_w=1200, thumb_w=300):
    filename = secure_filename(file_storage.filename or '')
    if not filename or not allowed_filename(filename):
        return None
    ext = filename.rsplit('.',1)[1].lower()
    idname = f"{prefix}_{make_id()}.{ext}"
    path = os.path.join(UPLOAD_FOLDER, idname)

    # open and resize
    try:
        img = Image.open(file_storage.stream)
        img = img.convert('RGB')
        w,h = img.size
        if w > max_w:
            nh = int(max_w * (h / w))
            img = img.resize((max_w, nh), Image.LANCZOS)
        # save with reasonable quality
        img.save(path, optimize=True, quality=80)
        return idname
    except Exception:
        return None

# ----------------------------
# User helpers
# ----------------------------

def user_to_dict(row):
    if row is None: return None
    return {'id': row['id'], 'username': row['username'], 'email': row['email'], 'bio': row['bio'], 'avatar_path': row['avatar_path'], 'is_admin': bool(row['is_admin']), 'created_at': row['created_at']}


def get_user_by_id(user_id: str):
    r = query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)
    return user_to_dict(r)


def get_user_by_username(username: str):
    r = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    return user_to_dict(r)

# ----------------------------
# Routes: Auth & Profile
# ----------------------------

@app.route('/register', methods=['POST'])
def register():
    data = request.json or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not username or not password or not email:
        return jsonify({'error':'username, email and password required'}), 400
    if query_db('SELECT id FROM users WHERE username = ? OR email = ?', (username, email), one=True):
        return jsonify({'error':'username or email already exists'}), 400
    password_hash = generate_password_hash(password)
    user_id = make_id()
    execute_db('INSERT INTO users (id, username, email, password_hash) VALUES (?,?,?,?)', (user_id, username, email, password_hash))
    access = create_access_token(user_id)
    refresh = create_refresh_token(user_id)
    user = get_user_by_id(user_id)
    return jsonify({'user': user, 'access_token': access, 'refresh_token': refresh})

@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    identifier = (data.get('username') or data.get('email') or '').strip()
    password = data.get('password') or ''
    if not identifier or not password:
        return jsonify({'error':'username/email and password required'}), 400
    row = query_db('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier), one=True)
    if not row or not check_password_hash(row['password_hash'], password):
        return jsonify({'error':'Invalid credentials'}), 401
    access = create_access_token(row['id'])
    refresh = create_refresh_token(row['id'])
    return jsonify({'user': user_to_dict(row), 'access_token': access, 'refresh_token': refresh})

@app.route('/token/refresh', methods=['POST'])
def refresh_token():
    data = request.json or {}
    token = data.get('refresh_token')
    if not token:
        return jsonify({'error':'refresh_token required'}), 400
    decoded = decode_refresh(token)
    if not decoded:
        return jsonify({'error':'Invalid refresh token'}), 401
    new_access = create_access_token(decoded['sub'])
    return jsonify({'access_token': new_access})

@app.route('/me', methods=['GET'])
@jwt_required
def me():
    return jsonify({'user': g.current_user})

@app.route('/me', methods=['PUT'])
@jwt_required
def update_profile():
    data = request.form or {}
    bio = (data.get('bio') or '').strip()
    avatar = request.files.get('avatar')
    avatar_path = None
    if avatar:
        saved = save_and_optimize_image(avatar, prefix='avatar', max_w=400)
        if saved:
            avatar_path = saved
        else:
            return jsonify({'error':'Invalid avatar upload'}), 400
    if avatar_path:
        execute_db('UPDATE users SET bio = ?, avatar_path = ? WHERE id = ?', (bio, avatar_path, g.current_user['id']))
    else:
        execute_db('UPDATE users SET bio = ? WHERE id = ?', (bio, g.current_user['id']))
    user = get_user_by_id(g.current_user['id'])
    return jsonify({'user': user})

@app.route('/users/<username>', methods=['GET'])
def public_profile(username):
    u = get_user_by_username(username)
    if not u: return jsonify({'error':'User not found'}), 404
    followers = query_db('SELECT COUNT(*) as c FROM follows WHERE following_id = ?', (u['id'],), one=True)['c']
    following = query_db('SELECT COUNT(*) as c FROM follows WHERE follower_id = ?', (u['id'],), one=True)['c']
    return jsonify({'user': u, 'followers': followers, 'following': following})

# ----------------------------
# Follow / Unfollow
# ----------------------------
@app.route('/follow/<target_id>', methods=['POST'])
@jwt_required
def follow_route(target_id):
    if target_id == g.current_user['id']:
        return jsonify({'error':'Cannot follow yourself'}), 400
    if not query_db('SELECT 1 FROM users WHERE id = ?', (target_id,), one=True):
        return jsonify({'error':'Target not found'}), 404
    rel = query_db('SELECT id FROM follows WHERE follower_id = ? AND following_id = ?', (g.current_user['id'], target_id), one=True)
    if rel:
        execute_db('DELETE FROM follows WHERE id = ?', (rel['id'],))
        return jsonify({'status':'unfollowed'})
    else:
        execute_db('INSERT INTO follows (id, follower_id, following_id) VALUES (?,?,?)', (make_id(), g.current_user['id'], target_id))
        # notify target
        execute_db('INSERT INTO notifications (id, user_id, type, payload) VALUES (?,?,?,?)', (make_id(), target_id, 'follow', g.current_user['id']))
        return jsonify({'status':'followed'})

# ----------------------------
# Posts, Likes, Comments
# ----------------------------
@app.route('/posts', methods=['POST'])
@jwt_required
def create_post():
    content = (request.form.get('content') or '')
    file = request.files.get('image')
    image_path = None
    if file:
        saved = save_and_optimize_image(file, prefix='post', max_w=1200)
        if not saved:
            return jsonify({'error':'Invalid image upload'}), 400
        image_path = saved
    post_id = make_id()
    execute_db('INSERT INTO posts (id, user_id, content, image_path) VALUES (?,?,?,?)', (post_id, g.current_user['id'], content, image_path))
    return jsonify({'post_id': post_id}), 201

@app.route('/posts/<post_id>', methods=['GET'])
def get_post(post_id):
    r = query_db('SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?', (post_id,), one=True)
    if not r: return jsonify({'error':'Post not found'}), 404
    likes = query_db('SELECT COUNT(*) as c FROM likes WHERE post_id = ?', (post_id,), one=True)['c']
    comments = query_db('SELECT COUNT(*) as c FROM comments WHERE post_id = ?', (post_id,), one=True)['c']
    viewer_id = g.current_user['id'] if hasattr(g, 'current_user') and g.current_user else None
    liked_by_me = False
    if viewer_id:
        liked_by_me = bool(query_db('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?', (post_id, viewer_id), one=True))
    return jsonify({'id': r['id'], 'user': {'id': r['user_id'], 'username': r['username']}, 'content': r['content'], 'image_url': f"/uploads/{r['image_path']}" if r['image_path'] else None, 'likes': likes, 'comments': comments, 'liked_by_me': liked_by_me})

@app.route('/posts/<post_id>/like', methods=['POST'])
@jwt_required
def like_post(post_id):
    exists = query_db('SELECT id FROM likes WHERE post_id = ? AND user_id = ?', (post_id, g.current_user['id']), one=True)
    if exists:
        execute_db('DELETE FROM likes WHERE id = ?', (exists['id'],))
        return jsonify({'status':'unliked'})
    else:
        execute_db('INSERT INTO likes (id, user_id, post_id) VALUES (?,?,?)', (make_id(), g.current_user['id'], post_id))
        # notify post owner
        owner = query_db('SELECT user_id FROM posts WHERE id = ?', (post_id,), one=True)
        if owner and owner['user_id'] != g.current_user['id']:
            execute_db('INSERT INTO notifications (id, user_id, type, payload) VALUES (?,?,?,?)', (make_id(), owner['user_id'], 'like', post_id))
        return jsonify({'status':'liked'})

@app.route('/posts/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
    rows = query_db('SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE post_id = ? ORDER BY created_at ASC', (post_id,))
    out = [{'id': r['id'], 'user': {'id': r['user_id'], 'username': r['username']}, 'content': r['content'], 'created_at': r['created_at']} for r in rows]
    return jsonify({'comments': out})

@app.route('/posts/<post_id>/comments', methods=['POST'])
@jwt_required
def post_comment(post_id):
    data = request.json or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error':'content required'}), 400
    cid = make_id()
    execute_db('INSERT INTO comments (id, user_id, post_id, content) VALUES (?,?,?,?)', (cid, g.current_user['id'], post_id, content))
    owner = query_db('SELECT user_id FROM posts WHERE id = ?', (post_id,), one=True)
    if owner and owner['user_id'] != g.current_user['id']:
        execute_db('INSERT INTO notifications (id, user_id, type, payload) VALUES (?,?,?,?)', (make_id(), owner['user_id'], 'comment', post_id))
    return jsonify({'comment_id': cid}), 201

# ----------------------------
# Feed, Explore, Search
# ----------------------------
@app.route('/feed', methods=['GET'])
@jwt_required
def feed():
    try:
        limit = min(int(request.args.get('limit', 20)), 100)
        offset = int(request.args.get('offset', 0))
    except ValueError:
        return jsonify({'error':'limit/offset must be integers'}), 400
    rows = query_db('''
        SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id
        WHERE p.user_id = ? OR p.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?)
        ORDER BY p.created_at DESC LIMIT ? OFFSET ?
    ''', (g.current_user['id'], g.current_user['id'], limit, offset))
    posts = []
    for r in rows:
        posts.append({'id': r['id'], 'user': {'id': r['user_id'], 'username': r['username']}, 'content': r['content'], 'image_url': f"/uploads/{r['image_path']}" if r['image_path'] else None, 'created_at': r['created_at']})
    return jsonify({'posts': posts})

@app.route('/explore', methods=['GET'])
def explore():
    rows = query_db('SELECT p.*, u.username, (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as likes FROM posts p JOIN users u ON p.user_id=u.id ORDER BY likes DESC LIMIT 50')
    return jsonify([{'id':r['id'], 'user':{'id':r['user_id'],'username':r['username']}, 'content': r['content'], 'image_url': f"/uploads/{r['image_path']}" if r['image_path'] else None, 'likes': r['likes']} for r in rows])

@app.route('/search_users', methods=['GET'])
def search_users():
    q = (request.args.get('q') or '').strip()
    if not q: return jsonify({'results': []})
    qlike = f"%{q}%"
    rows = query_db('SELECT id, username, bio FROM users WHERE username LIKE ? OR email LIKE ? LIMIT 50', (qlike, qlike))
    return jsonify({'results': [{'id':r['id'],'username':r['username'],'bio':r['bio']} for r in rows]})

# ----------------------------
# Messages (simple DM)
# ----------------------------
@app.route('/messages/send', methods=['POST'])
@jwt_required
def send_message():
    data = request.json or {}
    to_id = data.get('to')
    content = (data.get('content') or '').strip()
    if not to_id or not content:
        return jsonify({'error':'to and content required'}), 400
    mid = make_id()
    execute_db('INSERT INTO messages (id, sender_id, receiver_id, content) VALUES (?,?,?,?)', (mid, g.current_user['id'], to_id, content))
    execute_db('INSERT INTO notifications (id, user_id, type, payload) VALUES (?,?,?,?)', (make_id(), to_id, 'message', g.current_user['id']))
    return jsonify({'msg_id': mid}), 201

@app.route('/messages', methods=['GET'])
@jwt_required
def list_messages():
    other = request.args.get('with')
    if other:
        rows = query_db('SELECT * FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY created_at ASC', (g.current_user['id'], other, other, g.current_user['id']))
    else:
        rows = query_db('SELECT * FROM messages WHERE sender_id=? OR receiver_id=? ORDER BY created_at DESC LIMIT 100', (g.current_user['id'], g.current_user['id']))
    out = [{'id':r['id'], 'sender':r['sender_id'], 'receiver':r['receiver_id'], 'content':r['content'], 'created_at':r['created_at']} for r in rows]
    return jsonify({'messages': out})

# ----------------------------
# Notifications
# ----------------------------
@app.route('/notifications', methods=['GET'])
@jwt_required
def notifications():
    rows = query_db('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50', (g.current_user['id'],))
    out = [{'id':r['id'],'type':r['type'],'payload':r['payload'],'read':bool(r['read']),'created_at':r['created_at']} for r in rows]
    return jsonify({'notifications': out})

@app.route('/notifications/mark_read', methods=['POST'])
@jwt_required
def mark_read():
    data = request.json or {}
    nid = data.get('id')
    if not nid: return jsonify({'error':'id required'}), 400
    execute_db('UPDATE notifications SET read=1 WHERE id=? AND user_id=?', (nid, g.current_user['id']))
    return jsonify({'status':'ok'})

# ----------------------------
# Upload serve
# ----------------------------
@app.route('/uploads/<path:filename>', methods=['GET'])
def uploaded_file(filename):
    safe = os.path.normpath(filename)
    if safe.startswith('..'):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, filename)

# ----------------------------
# Admin endpoints
# ----------------------------
@app.route('/admin/users', methods=['GET'])
@jwt_required
def admin_users():
    if not g.current_user.get('is_admin'):
        return jsonify({'error':'admin only'}), 403
    rows = query_db('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC')
    return jsonify([dict(r) for r in rows])

# ----------------------------
# Lightweight rate limiter (per-IP simple)
# ----------------------------
RATE_BUCKET = {}
RATE_LIMIT = int(os.environ.get('SOCIAL_RATE_LIMIT', '100'))
RATE_WINDOW = int(os.environ.get('SOCIAL_RATE_WINDOW', '60'))

@app.before_request
def simple_rate_limit():
    ip = request.headers.get('X-Real-IP') or request.remote_addr
    now = int(datetime.datetime.utcnow().timestamp())
    bucket = RATE_BUCKET.get(ip, {'ts': now, 'count': 0})
    if now - bucket['ts'] > RATE_WINDOW:
        bucket = {'ts': now, 'count': 1}
    else:
        bucket['count'] += 1
    RATE_BUCKET[ip] = bucket
    if bucket['count'] > RATE_LIMIT:
        return jsonify({'error':'rate limit exceeded'}), 429

# ----------------------------
# Embedded Premium UI (cozy styling)
# Note: big chunk of HTML/CSS/JS. Kept inside file for single-file requirement.
# ----------------------------
INDEX_HTML = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Cozy Social — Demo (Educational)</title>
  <style>
    :root{
      --bg:#0f1724; --card:#0b1220; --muted:#9aa6b2; --accent:#7c5cff; --glass: rgba(255,255,255,0.03);
      --radius:14px; --gap:16px; --max:1000px;
    }
    *{box-sizing:border-box}
    body{background:linear-gradient(180deg,#071029 0%, #0b1220 100%);color:#e6eef6;font-family:Inter, ui-sans-serif, system-ui; margin:0; padding:28px; display:flex; justify-content:center}
    .app{width:100%;max-width:var(--max)}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
    .brand{display:flex;align-items:center;gap:12px}
    .logo{width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,var(--accent),#4f8bff);display:flex;align-items:center;justify-content:center;font-weight:700}
    .nav{display:flex;gap:8px}
    .card{background:var(--card);border-radius:var(--radius);padding:16px;box-shadow: 0 6px 30px rgba(2,6,23,0.6);}
    .grid{display:grid;grid-template-columns: 1fr 340px;gap:var(--gap)}
    .feed{display:flex;flex-direction:column;gap:12px}
    .post{background:var(--glass);padding:12px;border-radius:12px}
    input,textarea,button{font-family:inherit}
    input,textarea{background:transparent;border:1px solid rgba(255,255,255,0.06);padding:10px;border-radius:10px;color:inherit;width:100%}
    button{background:var(--accent);border:none;color:white;padding:10px 12px;border-radius:10px}
    .small{color:var(--muted);font-size:13px}
    .sidebar{display:flex;flex-direction:column;gap:12px}
    .user-card{display:flex;gap:12px;align-items:center}
    .avatar{width:56px;height:56px;border-radius:12px;background:linear-gradient(135deg,#334155,#0ea5a4);display:flex;align-items:center;justify-content:center}
    .muted{color:var(--muted)}
    .search input{padding-left:36px}
    .pill{background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:999px}
  </style>
</head>
<body>
<div class="app">
  <header>
    <div class="brand">
      <div class="logo">CS</div>
      <div>
        <div style="font-weight:700">Cozy Social</div>
        <div class="small">Premium demo UI</div>
      </div>
    </div>
    <div class="nav">
      <button onclick="goto('/home')" class="pill">Home</button>
      <button onclick="goto('/explore')" class="pill">Explore</button>
      <button onclick="goto('/messages')" class="pill">Messages</button>
      <button onclick="goto('/profile')" class="pill">Profile</button>
      <button onclick="logout()" class="pill" id="logoutBtn" style="display:none">Logout</button>
    </div>
  </header>

  <main class="grid">
    <section>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            <div style="font-weight:700">Create Post</div>
            <div class="small">Share something cozy</div>
          </div>
          <div class="small">Tip: This demo omits XSS prevention (educational)</div>
        </div>
        <div style="margin-top:12px;display:flex;flex-direction:column;gap:8px">
          <textarea id="postContent" placeholder="What's on your mind?"></textarea>
          <input type="file" id="postImage" accept="image/*" />
          <div style="display:flex;gap:8px">
            <button onclick="createPost()">Post</button>
            <button onclick="loadFeed()" class="small">Refresh</button>
          </div>
        </div>
      </div>

      <div id="feed" style="margin-top:16px" class="feed"></div>
    </section>

    <aside class="sidebar">
      <div class="card user-card">
        <div class="avatar" id="avatarPreview">U</div>
        <div>
          <div id="meUsername" style="font-weight:700">Guest</div>
          <div class="small" id="meEmail"></div>
        </div>
      </div>

      <div class="card search">
        <div style="font-weight:700">Search</div>
        <input id="searchQ" placeholder="Search users..." />
        <div id="searchResults" style="margin-top:8px"></div>
      </div>

      <div class="card">
        <div style="font-weight:700">Following</div>
        <div id="followingList" class="small" style="margin-top:8px"></div>
      </div>

    </aside>
  </main>
</div>

<script>
const api = (path, opts={}) => fetch(path, opts);
function setToken(t){ if(t) localStorage.setItem('access', t); else localStorage.removeItem('access'); }
function getToken(){ return localStorage.getItem('access'); }
async function goto(p){ if(p==='/home') loadFeed(); if(p==='/explore') loadExplore(); if(p==='/messages') loadMessages(); if(p==='/profile') loadProfile(); }
function showLogged(user){ if(user){ document.getElementById('meUsername').innerText=user.username; document.getElementById('meEmail').innerText=user.email||''; document.getElementById('logoutBtn').style.display='inline-block'; } }
async function registerDemo(){ const u=prompt('username'); const e=prompt('email'); const p=prompt('password'); if(!u||!p) return; const res = await api('/register', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u,email:e,password:p})}); alert(JSON.stringify(await res.json())); }
async function loginDemo(){ const id=prompt('username or email'); const p=prompt('password'); const res = await api('/login',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({username:id,password:p})}); const j=await res.json(); if(res.ok){ setToken(j.access_token); showLogged(j.user); loadFeed(); } else alert(JSON.stringify(j)); }
function logout(){ setToken(null); location.reload(); }

async function createPost(){ const token=getToken(); const content=document.getElementById('postContent').value; const file=document.getElementById('postImage').files[0]; if(!token){ alert('Please login'); return; }
 if(file){ const fd=new FormData(); fd.append('content',content); fd.append('image',file); const res=await fetch('/posts',{method:'POST',body:fd, headers:{'Authorization':'Bearer '+token}}); const j=await res.json(); if(!res.ok) alert(JSON.stringify(j)); else { document.getElementById('postContent').value=''; document.getElementById('postImage').value=''; loadFeed(); } } else { const res=await fetch('/posts',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body: JSON.stringify({content})}); const j=await res.json(); if(!res.ok) alert(JSON.stringify(j)); else loadFeed(); } }

function formatPost(p){ return `<div class="post card"><div style="display:flex;justify-content:space-between"><div><strong>@${p.user.username}</strong><div class="small">${p.created_at}</div></div><div><button onclick="likePost('${p.id}')">Like</button></div></div><div style="margin-top:8px">${p.content||''}</div>${p.image_url?`<div style="margin-top:8px"><img src='${p.image_url}' style='width:100%;border-radius:8px;'/></div>`:''}<div class="small" style="margin-top:8px">Likes: ${p.likes_count||0} Comments: ${p.comments_count||0} <button onclick="showComments('${p.id}')">Comments</button></div><div id='comments-${p.id}'></div></div>` }

async function loadFeed(){ const token=getToken(); const res = await fetch('/feed', {headers: token?{'Authorization':'Bearer '+token}:{}}); if(res.status===401){ /* not logged */ } const j=await res.json(); const feed=document.getElementById('feed'); feed.innerHTML=''; if(j.posts) j.posts.forEach(p=> feed.insertAdjacentHTML('beforeend', formatPost(p))); }

async function likePost(postId){ const token=getToken(); if(!token){ alert('login'); return; } const res=await fetch('/posts/'+postId+'/like',{method:'POST',headers:{'Authorization':'Bearer '+token}}); const j=await res.json(); if(!res.ok) alert(JSON.stringify(j)); else loadFeed(); }
async function showComments(postId){ const res=await fetch('/posts/'+postId+'/comments'); const j=await res.json(); const container=document.getElementById('comments-'+postId); container.innerHTML=''; if(j.comments) j.comments.forEach(c=> container.insertAdjacentHTML('beforeend', `<div class='small'><strong>@${c.user.username}</strong>: ${c.content}</div>`)); container.insertAdjacentHTML('beforeend', `<div><input id='c-${postId}' placeholder='Write comment'/> <button onclick="postComment('${postId}')">Send</button></div>`); }
async function postComment(postId){ const token=getToken(); const content=document.getElementById('c-'+postId).value; const res=await fetch('/posts/'+postId+'/comments',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body: JSON.stringify({content})}); const j=await res.json(); if(!res.ok) alert(JSON.stringify(j)); else showComments(postId); }

async function loadExplore(){ const res=await fetch('/explore'); const j=await res.json(); const feed=document.getElementById('feed'); feed.innerHTML=''; j.forEach(p=> feed.insertAdjacentHTML('beforeend', formatPost(p))); }
async function loadMessages(){ const token=getToken(); if(!token){ alert('login'); return; } const res=await fetch('/messages',{headers:{'Authorization':'Bearer '+token}}); const j=await res.json(); alert(JSON.stringify(j)); }
async function loadProfile(){ const token=getToken(); if(!token){ alert('login'); return; } const res=await fetch('/me',{headers:{'Authorization':'Bearer '+token}}); const j=await res.json(); if(res.ok) showLogged(j.user); else alert('not logged'); }

// quick bind: if token present, try /me
(async()=>{ const t=getToken(); if(!t) return; const res=await fetch('/me',{headers:{'Authorization':'Bearer '+t}}); if(res.ok){ const j=await res.json(); showLogged(j.user); loadFeed(); } else { localStorage.removeItem('access'); } })();
</script>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index_ui():
    return render_template_string(INDEX_HTML)

# ----------------------------
# Security headers & errors
# ----------------------------
@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Frame-Options','DENY')
    resp.headers.setdefault('X-Content-Type-Options','nosniff')
    resp.headers.setdefault('Referrer-Policy','no-referrer-when-downgrade')
    resp.headers.setdefault('Permissions-Policy','geolocation=()')
    # CSP intentionally permissive (demo). In production tighten this.
    resp.headers.setdefault('Content-Security-Policy', "default-src 'self' 'unsafe-inline' data:; img-src 'self' data:;")
    return resp

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error':'Uploaded file too large'}), 413

# ----------------------------
# Startup
# ----------------------------
if __name__ == '__main__':
    # dev server — for production use gunicorn
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT','5000')), debug=os.environ.get('FLASK_DEBUG','0')=='1')
