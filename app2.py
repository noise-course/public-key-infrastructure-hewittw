from flask import Flask, request, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import json
from pathlib import Path

"""
This code was made with the help of ChatGPT, intended to prove how HTTPS is more secure than HTTP.
"""

app = Flask(__name__)
app.secret_key = "replace_this_with_a_random_secret"  # change for your machine

USERS_FILE = Path("users.json")

def load_users():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text())

def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2))

@app.route("/")
def home():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            return "username and password required", 400

        users = load_users()
        if username in users:
            return "username already taken", 400

        users[username] = generate_password_hash(password)
        save_users(users)
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()
        hashed = users.get(username)
        if not hashed or not check_password_hash(hashed, password):
            return "invalid credentials", 401

        session["username"] = username
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    user = session.get("username")
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=user)

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    # these settings are not important for the assignment, but left them for fun (they improve security)
    app.config.update(
        SESSION_COOKIE_SECURE=True,      # send session cookie only over HTTPS
        SESSION_COOKIE_HTTPONLY=True,    # mitigate XSS cookie theft
        SESSION_COOKIE_SAMESITE="Lax",   # fine for this demo
        PREFERRED_URL_SCHEME="https",
    )
    # Use your filenames here:
    # For OpenSSL output:
    ssl_ctx = ("cert.pem", "key.pem")
    # For mkcert output (example names):
    # ssl_ctx = ("localhost+1.pem", "localhost+1-key.pem")

    app.run(host="0.0.0.0", port=8443, debug=True, ssl_context=ssl_ctx)

