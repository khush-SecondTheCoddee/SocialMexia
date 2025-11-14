Simple single-file social media app using Flask + JWT + sqlite3.

Features:
- User registration & login (JWT-based auth)
- Profiles (view & update)
- Follow / unfollow
- Create posts (text + optional image upload or base64)
- Feed of posts (from you + people you follow)
- Like / unlike posts
- Comment on posts
- Search users
- SQLite database (single file)
- Minimal, easy-to-read code suitable for extension

Dependencies:
- Flask
- PyJWT
- Flask-CORS (optional but recommended)
Install: pip install flask pyjwt flask-cors

Run:
    python app.py
Then use an API client (Postman, curl) to talk to the endpoints below.

Notes:
- This is an educational starting point. For production, use stronger secrets, HTTPS, better file handling, proper CORS config, input validation, rate-limits, and consider a more robust DB.
- Image uploads are saved into ./uploads (created automatically).
