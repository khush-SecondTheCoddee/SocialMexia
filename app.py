import base64
import datetime
import sqlite3
import jwt
import uuid
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os

# -------------------------
# CONFIGURATION
# -------------------------

app = Flask(__name__, static_folder='static')
CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret-key-123"
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

DATABASE = "database.db"

# -------------------------
# DATABASE SETUP
# -------------------------

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        caption TEXT,
        image BLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# -------------------------
# JWT UTILITIES
# -------------------------

def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")

def auth_required(func):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ")[1]

        try:
            decoded = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            request.user_id = decoded["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# -------------------------
# AUTH ROUTES
# -------------------------

@app.post("/sign-up")
def sign_up():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user_id = str(uuid.uuid4())

    try:
        query_db("INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
                 (user_id, username, password))
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 400

    return jsonify({"message": "Account created successfully"}), 201


@app.post("/login")
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = query_db("SELECT * FROM users WHERE username = ? AND password = ?", (username, password), one=True)

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user["id"])
    return jsonify({"token": token})

# -------------------------
# POST ROUTES
# -------------------------

@app.post("/create-post")
@auth_required
def create_post():
    caption = request.form.get("caption", "")
    image_file = request.files.get("image")

    if not image_file:
        return jsonify({"error": "Image file required"}), 400

    image_binary = image_file.read()
    post_id = str(uuid.uuid4())

    query_db("""
        INSERT INTO posts (id, user_id, caption, image)
        VALUES (?, ?, ?, ?)
    """, (post_id, request.user_id, caption, image_binary))

    return jsonify({"message": "Post created successfully"})


@app.get("/posts")
@auth_required
def get_posts():
    posts = query_db("""
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    """)

    result = [{
        "id": p["id"],
        "username": p["username"],
        "caption": p["caption"],
        "image": base64.b64encode(p["image"]).decode() if p["image"] else None,
        "created_at": p["created_at"]
    } for p in posts]

    return jsonify(result)

# -------------------------
# FRONTEND PAGES
# -------------------------

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial; margin: 40px; }}
        input, button {{ padding: 8px; margin: 5px; }}
    </style>
</head>
<body>
    <h1>{heading}</h1>
    {content}
</body>
</html>
"""

@app.get("/")
def index():  # landing
    return BASE_HTML.format(
        title="Welcome",
        heading="Welcome",
        content="""
        <p>Go to <a href='/home'>Home</a> or <a href='/sign-up'>Sign Up</a></p>
        """
    )

@app.get("/home")
def home_page():
    return BASE_HTML.format(
        title="Home",
        heading="Home Page",
        content="""
        <p>Login to view posts.</p>
        <a href="/login">Login</a>
        """
    )

@app.get("/sign-up")
def signup_page():
    return BASE_HTML.format(
        title="Sign Up",
        heading="Create an Account",
        content="""
        <form onsubmit="submitForm(event)">
            <input placeholder="Username" id="username"><br>
            <input type="password" placeholder="Password" id="password"><br>
            <button>Sign Up</button>
        </form>

        <script>
        async function submitForm(e){
            e.preventDefault();
            let username = document.getElementById('username').value;
            let password = document.getElementById('password').value;

            let res = await fetch('/sign-up', {
               method: 'POST',
               headers: {'Content-Type':'application/json'},
               body: JSON.stringify({username, password})
            });

            let data = await res.json();
            alert(JSON.stringify(data));
        }
        </script>
        """
    )

@app.get("/login")
def login_page():
    return BASE_HTML.format(
        title="Login",
        heading="Login",
        content="""
        <form onsubmit="login(event)">
            <input placeholder="Username" id="username"><br>
            <input type="password" placeholder="Password" id="password"><br>
            <button>Login</button>
        </form>

        <script>
        async function login(e){
            e.preventDefault();
            let username = document.getElementById('username').value;
            let password = document.getElementById('password').value;

            let res = await fetch('/login', {
               method: 'POST',
               headers: {'Content-Type':'application/json'},
               body: JSON.stringify({username, password})
            });

            let data = await res.json();
            if(data.token){
                localStorage.setItem('token', data.token);
                alert('Logged in!');
                window.location.href='/profile';
            } else {
                alert(JSON.stringify(data));
            }
        }
        </script>
        """
    )

@app.get("/profile")
def profile_page():
    return BASE_HTML.format(
        title="Profile",
        heading="Your Profile",
        content="""
        <p><button onclick="loadPosts()">Load Posts</button></p>
        <div id="posts"></div>

        <script>
        async function loadPosts(){
            let token = localStorage.getItem('token');
            let res = await fetch('/posts', {
                headers: {"Authorization": "Bearer " + token}
            });

            let posts = await res.json();
            let html = "";

            posts.forEach(p=>{
                html += `<div><h3>@${p.username}</h3><p>${p.caption}</p>
                         <img src="data:image/png;base64,${p.image}" width="200"></div><hr>`;
            });

            document.getElementById('posts').innerHTML = html;
        }
        </script>
        """
    )

# -------------------------
# RUN APP
# -------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=False)
