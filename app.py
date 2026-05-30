import os
import re
from datetime import datetime, timezone, timedelta

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

from static.db import hash_password, verify_password


# ─────────────────────────────────────────────────────────────
# Load Environment Variables
# ─────────────────────────────────────────────────────────────

load_dotenv()

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017/"
)

JWT_SECRET = os.getenv(
    "JWT_SECRET",
    "change-this-secret"
)

JWT_ALGORITHM = "HS256"

JWT_EXPIRY_MINS = int(
    os.getenv("JWT_EXPIRY_MINUTES", "60")
)


# ─────────────────────────────────────────────────────────────
# Flask Setup
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)

app.secret_key = "super-secret-key-change-me"

CORS(
    app,
    supports_credentials=True
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[
        "200 per day",
        "50 per hour"
    ],
    storage_uri="memory://"
)


# ─────────────────────────────────────────────────────────────
# MongoDB
# ─────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)

database = client["users"]

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
        "exp": datetime.now(timezone.utc)
        + timedelta(minutes=JWT_EXPIRY_MINS)
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def get_current_user():

    token = request.cookies.get("auth_token")

    if not token:
        return None

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        return payload.get("sub")

    except JWTError:
        return None


# ─────────────────────────────────────────────────────────────
# Pages
# ─────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("signup.html")


@app.route("/signin", methods=["GET"])
def signin_page():
    return render_template("signin.html")


@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/signin")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# ─────────────────────────────────────────────────────────────
# Signup
# ─────────────────────────────────────────────────────────────

@app.route("/signup", methods=["POST"])
@limiter.limit("10 per minute")
def signup():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "message": "Invalid JSON body"
        }), 400

    username = data.get(
        "username",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    full_name = data.get(
        "full_name",
        ""
    ).strip()

    mobile = data.get(
        "mobile",
        ""
    ).strip()

    dob = data.get(
        "dob",
        ""
    ).strip()

    error = validate_input(
        username,
        password
    )

    if error:
        return jsonify({
            "success": False,
            "message": error
        }), 400

    if not full_name:
        return jsonify({
            "success": False,
            "message": "Full name is required"
        }), 400

    if not re.match(r"^\d{10}$", mobile):
        return jsonify({
            "success": False,
            "message": "Enter a valid 10-digit mobile number"
        }), 400

    if not dob:
        return jsonify({
            "success": False,
            "message": "Date of birth is required"
        }), 400

    existing_user = users_collection.find_one({
        "username": username
    })

    if existing_user:
        return jsonify({
            "success": False,
            "message": "Username already taken"
        }), 409

    users_collection.insert_one({
        "username": username,
        "password": hash_password(password),
        "full_name": full_name,
        "mobile": mobile,
        "dob": dob,
        "created_at": datetime.now(timezone.utc),
        "is_active": True
    })

    return jsonify({
        "success": True,
        "message": "Account created successfully"
    }), 201


# ─────────────────────────────────────────────────────────────
# Signin
# ─────────────────────────────────────────────────────────────

@app.route("/signin", methods=["POST"])
@limiter.limit("10 per minute")
def signin():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "message": "Invalid JSON body"
        }), 400

    username = data.get(
        "username",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    user = users_collection.find_one({
        "username": username
    })

    if not user:
        return jsonify({
            "success": False,
            "message": "Invalid credentials"
        }), 401

    try:

        valid = verify_password(
            password,
            user["password"]
        )

    except Exception:

        return jsonify({
            "success": False,
            "message": "Password hash error. Delete old user and create a new account."
        }), 500

    if not valid:
        return jsonify({
            "success": False,
            "message": "Invalid credentials"
        }), 401

    session["username"] = username

    token = issue_jwt(username)

    response = make_response(
        jsonify({
            "success": True,
            "message": "Login successful"
        })
    )

    response.set_cookie(
        "auth_token",
        token,
        httponly=True,
        samesite="Lax",
        secure=False,
        max_age=JWT_EXPIRY_MINS * 60
    )

    return response


# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    response = make_response(
        jsonify({
            "success": True,
            "message": "Logged out"
        })
    )

    response.delete_cookie(
        "auth_token"
    )

    return response


# ─────────────────────────────────────────────────────────────
# Current User
# ─────────────────────────────────────────────────────────────

@app.route("/me")
def me():

    username = get_current_user()

    if not username:
        return jsonify({
            "success": False,
            "message": "Not authenticated"
        }), 401

    user = users_collection.find_one(
        {"username": username},
        {"_id": 0}
    )

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    return jsonify({
        "success": True,
        "username": user.get("username"),
        "full_name": user.get("full_name"),
        "mobile": user.get("mobile"),
        "dob": user.get("dob"),
        "created_at": str(user.get("created_at"))
    })


# ─────────────────────────────────────────────────────────────
# Run App
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)