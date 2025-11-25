#!/bin/bash

# --- Configuration ---
PROJECT_NAME="bharat_social_app"
PYTHON_DEPS="Flask Flask-SQLAlchemy Werkzeug"

echo "Starting setup for the minimal social media app: $PROJECT_NAME"

# 1. Create Project Directory
mkdir -p "$PROJECT_NAME"
cd "$PROJECT_NAME"

# 2. Setup Python Environment (Optional but Recommended)
echo "Setting up virtual environment..."
python3 -m venv venv
source venv/bin/activate

# 3. Install Dependencies
echo "Installing Python dependencies: $PYTHON_DEPS"
pip install $PYTHON_DEPS

# 4. Create Templates Directory
mkdir -p templates

# 5. Create app.py
echo "Creating app.py..."
cat << EOF > app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Helper (Mock Login State) ---
current_user = None 

def login_user(user):
    global current_user
    current_user = user

def logout_user():
    global current_user
    current_user = None

# --- Routes ---

@app.route('/')
def index():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=posts, user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'Logged in as {user.username}.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/post', methods=['POST'])
def create_post():
    if not current_user:
        flash('You must be logged in to post.', 'warning')
        return redirect(url_for('login'))
    
    content = request.form.get('content')
    if content:
        new_post = Post(content=content, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
EOF

# 6. Create HTML Templates
echo "Creating HTML templates..."

cat << EOF > templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bharat Social</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        .flash { padding: 10px; margin-bottom: 15px; border-radius: 5px; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
        .post { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <nav>
        <a href="{{ url_for('index') }}">Home</a> |
        {% if user %}
            <span>Logged in as: {{ user.username }}</span> |
            <a href="{{ url_for('logout') }}">Logout</a>
        {% else %}
            <a href="{{ url_for('login') }}">Login</a> |
            <a href="{{ url_for('register') }}">Register</a>
        {% endif %}
    </nav>
    <hr>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="flash {{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}
</body>
</html>
EOF

cat << EOF > templates/index.html
{% extends "base.html" %}

{% block content %}
    <h1>Social Feed</h1>

    {% if user %}
        <h2>What's on your mind, {{ user.username }}?</h2>
        <form method="POST" action="{{ url_for('create_post') }}">
            <textarea name="content" rows="4" cols="50" required></textarea><br>
            <button type="submit">Post</button>
        </form>
        <hr>
    {% endif %}

    {% for post in posts %}
        <div class="post">
            <p><strong>{{ post.author.username }}</strong> posted:</p>
            <p>{{ post.content }}</p>
            <small>{{ post.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
        </div>
    {% else %}
        <p>No posts yet. Be the first!</p>
    {% endfor %}
{% endblock %}
EOF

cat << EOF > templates/register.html
{% extends "base.html" %}

{% block content %}
    <h2>Register</h2>
    <form method="POST">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required><br><br>
        
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>
        
        <button type="submit">Register</button>
    </form>
{% endblock %}
EOF

cat << EOF > templates/login.html
{% extends "base.html" %}

{% block content %}
    <h2>Login</h2>
    <form method="POST">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required><br><br>
        
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>
        
        <button type="submit">Login</button>
    </form>
{% endblock %}
EOF

echo "Setup complete!"
echo ""
echo "----------------------------------------------------"
echo "To run your application:"
echo "1. Change directory: cd $PROJECT_NAME"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Run the app: python app.py"
echo "----------------------------------------------------"
