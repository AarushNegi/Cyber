import os
import re
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    make_response,
    render_template,
    session,
    redirect
)

from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from jose import jwt, JWTError
from dotenv import load_dotenv

from db import hash_password, verify_password


# ─────────────────────────────────────────────────────────────
# Environment Variables
# ─────────────────────────────────────────────────────────────

load_dotenv()

MONGO_URI       = os.getenv("MONGO_URI",           "mongodb://localhost:27017/")
JWT_SECRET      = os.getenv("JWT_SECRET",           "change-this-secret")
FLASK_SECRET    = os.getenv("FLASK_SECRET_KEY",     "change-this-secret")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRY_MINS = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
APP_ORIGIN      = os.getenv("APP_ORIGIN",           "http://localhost:5000")
IS_PRODUCTION   = os.getenv("FLASK_ENV", "development") == "production"


# ─────────────────────────────────────────────────────────────
# Flask Setup
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = FLASK_SECRET          # ← now from .env, not hardcoded

CORS(app, origins=[APP_ORIGIN], supports_credentials=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


# ─────────────────────────────────────────────────────────────
# MongoDB
# ─────────────────────────────────────────────────────────────

client           = MongoClient(MONGO_URI)
database         = client["users"]
users_collection = database["mails"]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def validate_input(username, password):
    if not username or not password:
        return "Username and password are required"
    if len(username) < 3 or len(username) > 32:
        return "Username must be between 3 and 32 characters"
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return "Username can only contain letters, numbers, _ . -"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    return None


def issue_jwt(username):
    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user():
    """Verify JWT from cookie. Returns username string or None."""
    token = request.cookies.get("auth_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


# ─────────────────────────────────────────────────────────────
# jwt_required decorator — SERVER-SIDE PROTECTION
# Wraps any route that needs a logged-in user.
# Works for both page routes (redirects) and API routes (returns 401).
# ─────────────────────────────────────────────────────────────

def jwt_required(redirect_on_fail=False):
    """
    Decorator that protects a route with JWT verification.

    Usage:
        @app.route("/dashboard")
        @jwt_required(redirect_on_fail=True)   # HTML pages  → redirect to /signin
        def dashboard(): ...

        @app.route("/me")
        @jwt_required()                        # API routes  → return 401 JSON
        def me(): ...
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            username = get_current_user()
            if not username:
                if redirect_on_fail:
                    return redirect("/signin")
                return jsonify({"success": False, "message": "Not authenticated"}), 401
            # Inject username into the function via Flask's g object substitute
            request.current_user = username
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ─────────────────────────────────────────────────────────────
# Page Routes
# ─────────────────────────────────────────────────────────────

@app.route("/")
def home():
    # If already logged in, send straight to dashboard
    if get_current_user():
        return redirect("/dashboard")
    return render_template("signup.html")


@app.route("/signin", methods=["GET"])
def signin_page():
    if get_current_user():
        return redirect("/dashboard")
    return render_template("signin.html")


@app.route("/dashboard")
@jwt_required(redirect_on_fail=True)      # ← SERVER-SIDE: JWT verified here
def dashboard():
    return render_template("dashboard.html")
    # Note: username is NOT passed via template anymore.
    # dashboard.html fetches /me with the JWT cookie — single source of truth.


# ─────────────────────────────────────────────────────────────
# Signup
# ─────────────────────────────────────────────────────────────

@app.route("/signup", methods=["POST"])
@limiter.limit("10 per minute")
def signup():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON body"}), 400

    username  = data.get("username",  "").strip()
    password  = data.get("password",  "")
    full_name = data.get("full_name", "").strip()
    mobile    = data.get("mobile",    "").strip()
    dob       = data.get("dob",       "").strip()

    error = validate_input(username, password)
    if error:
        return jsonify({"success": False, "message": error}), 400

    if not full_name:
        return jsonify({"success": False, "message": "Full name is required"}), 400

    if not re.match(r"^\d{10}$", mobile):
        return jsonify({"success": False, "message": "Enter a valid 10-digit mobile number"}), 400

    if not dob:
        return jsonify({"success": False, "message": "Date of birth is required"}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"success": False, "message": "Username already taken"}), 409

    users_collection.insert_one({
        "username":   username,
        "password":   hash_password(password),
        "full_name":  full_name,
        "mobile":     mobile,
        "dob":        dob,
        "created_at": datetime.now(timezone.utc),
        "is_active":  True
    })

    return jsonify({"success": True, "message": "Account created successfully"}), 201


# ─────────────────────────────────────────────────────────────
# Signin
# ─────────────────────────────────────────────────────────────

@app.route("/signin", methods=["POST"])
@limiter.limit("10 per minute")
def signin():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON body"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    user = users_collection.find_one({"username": username})

    # Same error for "not found" and "wrong password" — prevents username enumeration
    if not user:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    try:
        valid = verify_password(password, user["password"])
    except Exception:
        return jsonify({"success": False, "message": "Auth error — please re-register"}), 500

    if not valid:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    # Set Flask session AND issue JWT cookie — both cleared on logout
    session["username"] = username
    token    = issue_jwt(username)
    response = make_response(jsonify({"success": True, "message": "Login successful"}))
    response.set_cookie(
        "auth_token",
        token,
        httponly=True,
        samesite="Lax",
        secure=IS_PRODUCTION,          # ← True on live (HTTPS), False locally
        max_age=JWT_EXPIRY_MINS * 60
    )
    return response


# ─────────────────────────────────────────────────────────────
# Signout
# ─────────────────────────────────────────────────────────────

@app.route("/signout", methods=["POST"])
def signout():
    session.clear()
    response = make_response(jsonify({"success": True, "message": "Signed out"}))
    response.delete_cookie("auth_token")
    return response


# ─────────────────────────────────────────────────────────────
# /me — Protected API: returns current user's profile
# ─────────────────────────────────────────────────────────────

@app.route("/me")
@jwt_required()                           # ← API route: returns 401 if not authed
def me():
    username = request.current_user
    user = users_collection.find_one({"username": username}, {"_id": 0, "password": 0})

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    return jsonify({
        "success":    True,
        "username":   user.get("username"),
        "full_name":  user.get("full_name"),
        "mobile":     user.get("mobile"),
        "dob":        user.get("dob"),
        "created_at": str(user.get("created_at"))
    })


# ─────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)