import os
import re
import json
import base64
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    jsonify,
    make_response,
    render_template,
    session,
    redirect,
    url_for,
)

from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from jose import jwt, JWTError
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

from audit import (
    log_event,
    LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, SIGNUP,
    PASSKEY_REGISTERED, PASSKEY_DELETED, PASSKEY_RENAMED,
    GOOGLE_LOGIN, GOOGLE_SIGNUP,
)
from risk import calculate_risk, update_known_ips

import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.exceptions import InvalidCBORData

from db import hash_password, verify_password
from fido2_store import (
    save_challenge,
    get_challenge,
    save_credential,
    get_credentials_for_user,
    get_credential_by_id,
    update_sign_count,
    delete_credential,
)


# ─────────────────────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────────────────────

load_dotenv()

MONGO_URI            = os.getenv("MONGO_URI",           "mongodb://localhost:27017/")
JWT_SECRET           = os.getenv("JWT_SECRET",           "change-this-secret")
FLASK_SECRET         = os.getenv("FLASK_SECRET_KEY",     "change-this-secret")
JWT_ALGORITHM        = "HS256"
JWT_EXPIRY_MINS      = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
APP_ORIGIN           = os.getenv("APP_ORIGIN",           "http://localhost:5000")
IS_PRODUCTION        = os.getenv("FLASK_ENV", "development") == "production"
RP_ID                = os.getenv("RP_ID",   "localhost")
RP_NAME              = os.getenv("RP_NAME", "ZeroKey Auth")
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")


# ─────────────────────────────────────────────────────────────
# Flask
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = FLASK_SECRET

CORS(app, origins=[APP_ORIGIN], supports_credentials=True)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ─────────────────────────────────────────────────────────────
# Session cookie hardening
# ─────────────────────────────────────────────────────────────

app.config['SESSION_COOKIE_SECURE']   = IS_PRODUCTION
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ─────────────────────────────────────────────────────────────
# Security headers
# ─────────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]          = "no-store, no-cache, must-revalidate"
    response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https://lh3.googleusercontent.com; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self';"
  )
    return response



# ─────────────────────────────────────────────────────────────
# Google OAuth setup
# ─────────────────────────────────────────────────────────────

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# ─────────────────────────────────────────────────────────────
# MongoDB
# ─────────────────────────────────────────────────────────────

client            = MongoClient(MONGO_URI)
database          = client["users"]
users_collection  = database["mails"]
creds_collection  = database["fido2_credentials"]
audit_collection  = database["audit_logs"]


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


def issue_jwt(username, auth_method="password"):
    payload = {
        "sub":         username,
        "auth_method": auth_method,
        "iat":         datetime.now(timezone.utc),
        "exp":         datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user():
    token = request.cookies.get("auth_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


def get_client_ip():
    # Render sits behind a proxy — X-Forwarded-For has the real IP
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

LOCKOUT_ATTEMPTS = 5
LOCKOUT_MINUTES  = 15

def sanitise(value):
    """Block MongoDB operator injection — reject any dict input."""
    if isinstance(value, (dict, list)):
        return None
    return str(value) if value is not None else None

def is_account_locked(user: dict) -> tuple[bool, int]:
    locked_until = user.get("locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(timezone.utc):
            remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
            return True, remaining
    return False, 0


def record_failed_attempt(username: str) -> None:
    user = users_collection.find_one({"username": username})
    if not user:
        return
    attempts = user.get("failed_attempts", 0) + 1
    update = {"failed_attempts": attempts}
    if attempts >= LOCKOUT_ATTEMPTS:
        update["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        update["failed_attempts"] = 0   # reset so next cycle works
    users_collection.update_one({"username": username}, {"$set": update})

def reset_failed_attempts(username: str) -> None:
    users_collection.update_one(
        {"username": username},
        {"$set": {"failed_attempts": 0, "locked_until": None}}
    )


def jwt_required(redirect_on_fail=False):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            username = get_current_user()
            if not username:
                if redirect_on_fail:
                    return redirect("/signin")
                return jsonify({"success": False, "message": "Not authenticated"}), 401
            request.current_user = username
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ─────────────────────────────────────────────────────────────
# Page routes
# ─────────────────────────────────────────────────────────────

@app.route("/")
def home():
    if get_current_user():
        return redirect("/dashboard")
    return render_template("signup.html")


@app.route("/signin", methods=["GET"])
def signin_page():
    if get_current_user():
        return redirect("/dashboard")
    return render_template("signin.html")


@app.route("/dashboard")
@jwt_required(redirect_on_fail=True)
def dashboard():
    return render_template("dashboard.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


# ─────────────────────────────────────────────────────────────
# Signup
# ─────────────────────────────────────────────────────────────

@app.route("/signup", methods=["POST"])
@limiter.limit("10 per minute")
def signup():
    if os.getenv("REGISTRATION_OPEN", "true") == "false":
        return jsonify({"success": False, "message": "Registration is currently closed"}), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON body"}), 400

    username  = sanitise(data.get("username",  ""))
    password  = sanitise(data.get("password",  ""))
    full_name = sanitise(data.get("full_name", ""))
    mobile    = sanitise(data.get("mobile",    ""))
    dob       = sanitise(data.get("dob",       ""))

    if not all([username, password, full_name, mobile, dob]):
        return jsonify({"success": False, "message": "Invalid input"}), 400

    username  = username.strip()
    full_name = full_name.strip()
    mobile    = mobile.strip()
    dob       = dob.strip()
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
        "username":    username,
        "password":    hash_password(password),
        "full_name":   full_name,
        "mobile":      mobile,
        "dob":         dob,
        "auth_method": "password",
        "created_at":  datetime.now(timezone.utc),
        "is_active":   True
    })

    log_event(audit_collection, SIGNUP,
              username=username, ip=get_client_ip(),
              auth_method="password", success=True)

    return jsonify({"success": True, "message": "Account created successfully"}), 201


# ─────────────────────────────────────────────────────────────
# Signin — password
# ─────────────────────────────────────────────────────────────

@app.route("/signin", methods=["POST"])
@limiter.limit("10 per minute")
def signin():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON body"}), 400

    username = sanitise(data.get("username", ""))
    password = sanitise(data.get("password", ""))
    if not username or not password:
        return jsonify({"success": False, "message": "Invalid credentials"}), 400
    username = username.strip()
    ip= get_client_ip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    user = users_collection.find_one({"username": username})
    if not user:
        log_event(audit_collection, LOGIN_FAILURE,
                  username=username, ip=ip,
                  auth_method="password", success=False,
                  detail="User not found")
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    # ── Account lockout check ─────────────────────────────
    locked, minutes_left = is_account_locked(user)
    if locked:
        log_event(audit_collection, LOGIN_FAILURE,
                  username=username, ip=ip,
                  auth_method="password", success=False,
                  detail=f"Account locked — {minutes_left} min remaining")
        return jsonify({
            "success": False,
            "message": f"Account locked. Try again in {minutes_left} minute(s)."
        }), 423

    # ── Risk engine ───────────────────────────────────────
    risk = calculate_risk(user, ip, users_collection, audit_collection)
    if risk["action"] == "block":
        log_event(audit_collection, LOGIN_FAILURE,
                  username=username, ip=ip,
                  auth_method="password", success=False,
                  detail=f"Risk blocked — score {risk['score']} signals: {risk['signals']}")
        return jsonify({
            "success": False,
            "message": "Login blocked due to suspicious activity. Please use your passkey or try again later.",
            "risk_level": risk["level"]
        }), 403

    try:
        valid = verify_password(password, user["password"])
    except Exception:
        log_event(audit_collection, LOGIN_FAILURE,
                  username=username, ip=ip,
                  auth_method="password", success=False,
                  detail="Password hash error")
        return jsonify({"success": False, "message": "Auth error — please re-register"}), 500

    if not valid:
        record_failed_attempt(username)
        log_event(audit_collection, LOGIN_FAILURE,
                  username=username, ip=ip,
                  auth_method="password", success=False,
                  detail="Wrong password")
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    # ── Success — reset lockout counter ──────────────────
    reset_failed_attempts(username)
    update_known_ips(users_collection, username, ip)
    log_event(audit_collection, LOGIN_SUCCESS,
              username=username, ip=ip,
              auth_method="password", success=True,
              detail=f"risk:{risk['level']} score:{risk['score']}")

    session["username"] = username
    token    = issue_jwt(username, auth_method="password")
    response = make_response(jsonify({"success": True, "message": "Login successful"}))
    response.set_cookie(
        "auth_token", token,
        httponly=True, samesite="Lax",
        secure=IS_PRODUCTION,
        max_age=JWT_EXPIRY_MINS * 60
    )
    return response


# ─────────────────────────────────────────────────────────────
# Google OAuth
# ─────────────────────────────────────────────────────────────

@app.route("/auth/google")
def google_login():
    redirect_uri = APP_ORIGIN + "/auth/google/callback"
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    ip = get_client_ip()
    try:
        token     = google.authorize_access_token()
        user_info = token.get("userinfo")

        if not user_info:
            return redirect("/signin?error=google_failed")

        google_id  = user_info.get("sub")
        email      = user_info.get("email")
        full_name  = user_info.get("name", "")
        picture    = user_info.get("picture", "")

        base_username = re.sub(r"[^a-zA-Z0-9_.-]", "_", email.split("@")[0])[:32]

        user = users_collection.find_one({
            "$or": [
                {"google_id": google_id},
                {"email": email}
            ]
        })

        if user:
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "google_id":  google_id,
                    "picture":    picture,
                    "last_login": datetime.now(timezone.utc),
                }}
            )
            username = user["username"]
            log_event(audit_collection, GOOGLE_LOGIN,
                      username=username, ip=ip,
                      auth_method="google", success=True)
        else:
            if os.getenv("REGISTRATION_OPEN", "true") == "false":
                log_event(audit_collection, GOOGLE_SIGNUP,
                          username=None, ip=ip,
                          auth_method="google", success=False,
                          detail="Registration closed")
                return redirect("/signin?error=registration_closed")

            username = base_username
            counter  = 1
            while users_collection.find_one({"username": username}):
                username = f"{base_username}{counter}"
                counter += 1

            users_collection.insert_one({
                "username":    username,
                "full_name":   full_name,
                "email":       email,
                "google_id":   google_id,
                "picture":     picture,
                "password":    None,
                "mobile":      "",
                "dob":         "",
                "auth_method": "google",
                "created_at":  datetime.now(timezone.utc),
                "is_active":   True,
            })

            log_event(audit_collection, GOOGLE_SIGNUP,
                      username=username, ip=ip,
                      auth_method="google", success=True)

        session["username"] = username
        jwt_token = issue_jwt(username, auth_method="google")
        response  = make_response(redirect("/dashboard"))
        response.set_cookie(
            "auth_token", jwt_token,
            httponly=True, samesite="Lax",
            secure=IS_PRODUCTION,
            max_age=JWT_EXPIRY_MINS * 60
        )
        return response

    except Exception as e:
        print(f"Google OAuth error: {e}")
        log_event(audit_collection, GOOGLE_LOGIN,
                  username=None, ip=ip,
                  auth_method="google", success=False,
                  detail=str(e))
        return redirect("/signin?error=google_failed")


# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────

@app.route("/logout", methods=["POST"])
def logout():
    username = get_current_user()
    log_event(audit_collection, LOGOUT,
              username=username, ip=get_client_ip(),
              auth_method=None, success=True)
    session.clear()
    response = make_response(jsonify({"success": True, "message": "Logged out"}))
    response.delete_cookie("auth_token")
    return response


# ─────────────────────────────────────────────────────────────
# /me
# ─────────────────────────────────────────────────────────────

@app.route("/me")
@jwt_required()
def me():
    username = request.current_user
    user     = users_collection.find_one({"username": username}, {"_id": 0, "password": 0})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    passkey_count = creds_collection.count_documents({"username": username})

    return jsonify({
        "success":       True,
        "username":      user.get("username"),
        "full_name":     user.get("full_name"),
        "mobile":        user.get("mobile"),
        "dob":           user.get("dob"),
        "email":         user.get("email", ""),
        "picture":       user.get("picture", ""),
        "auth_method":   user.get("auth_method", "password"),
        "created_at":    str(user.get("created_at")),
        "passkey_count": passkey_count
    })


# ─────────────────────────────────────────────────────────────
# FIDO2 — Registration
# ─────────────────────────────────────────────────────────────

@app.route("/fido2/register/begin", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
def fido2_register_begin():
    username = request.current_user

    existing = get_credentials_for_user(creds_collection, username)
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=c["credential_id"])
        for c in existing
    ]

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        exclude_credentials=exclude_credentials,
    )

    save_challenge(username, options.challenge)

    return app.response_class(
        response=webauthn.options_to_json(options),
        mimetype="application/json"
    )


@app.route("/fido2/register/complete", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
def fido2_register_complete():
    username = request.current_user
    data     = request.get_json(silent=True)
    ip       = get_client_ip()

    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    challenge = get_challenge(username)
    if not challenge:
        return jsonify({"success": False, "message": "Challenge expired — please try again"}), 400

    try:
        verification = webauthn.verify_registration_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=APP_ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:
        log_event(audit_collection, PASSKEY_REGISTERED,
                  username=username, ip=ip,
                  auth_method="fido2", success=False,
                  detail=str(e))
        return jsonify({"success": False, "message": f"Verification failed: {str(e)}"}), 400

    save_credential(creds_collection, username, verification)

    log_event(audit_collection, PASSKEY_REGISTERED,
              username=username, ip=ip,
              auth_method="fido2", success=True)

    return jsonify({"success": True, "message": "Passkey registered successfully"})


# ─────────────────────────────────────────────────────────────
# FIDO2 — Passkey Management
# ─────────────────────────────────────────────────────────────

@app.route("/fido2/credentials", methods=["GET"])
@jwt_required()
def list_credentials():
    username = request.current_user
    creds    = get_credentials_for_user(creds_collection, username)
    result   = []
    for c in creds:
        result.append({
            "id":           c["credential_id"].hex() if isinstance(c["credential_id"], bytes) else str(c["credential_id"]),
            "device_name":  c.get("device_name", "My device"),
            "created_at":   str(c.get("created_at", "")),
            "last_used_at": str(c.get("last_used_at", "")),
        })
    return jsonify({"success": True, "credentials": result})


@app.route("/fido2/credential/<cred_id>", methods=["DELETE"])
@jwt_required()
def delete_credential_route(cred_id):
    username = request.current_user
    ip       = get_client_ip()
    total    = creds_collection.count_documents({"username": username})

    if total <= 1:
        return jsonify({"success": False, "message": "Cannot delete your only passkey — you would be locked out"}), 400

    try:
        cred_bytes = bytes.fromhex(cred_id)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid credential ID"}), 400

    deleted = delete_credential(creds_collection, cred_bytes, username)
    if not deleted:
        return jsonify({"success": False, "message": "Passkey not found"}), 404

    log_event(audit_collection, PASSKEY_DELETED,
              username=username, ip=ip,
              auth_method="fido2", success=True)

    return jsonify({"success": True, "message": "Passkey deleted"})


@app.route("/fido2/credential/<cred_id>/rename", methods=["PATCH"])
@jwt_required()
def rename_credential(cred_id):
    username = request.current_user
    ip       = get_client_ip()
    data     = request.get_json(silent=True)
    new_name = (data or {}).get("name", "").strip()

    if not new_name or len(new_name) > 40:
        return jsonify({"success": False, "message": "Name must be 1–40 characters"}), 400

    try:
        cred_bytes = bytes.fromhex(cred_id)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid credential ID"}), 400

    result = creds_collection.update_one(
        {"credential_id": cred_bytes, "username": username},
        {"$set": {"device_name": new_name}}
    )

    if result.matched_count == 0:
        return jsonify({"success": False, "message": "Passkey not found"}), 404

    log_event(audit_collection, PASSKEY_RENAMED,
              username=username, ip=ip,
              auth_method="fido2", success=True,
              detail=f"Renamed to: {new_name}")

    return jsonify({"success": True, "message": "Passkey renamed"})


# ─────────────────────────────────────────────────────────────
# FIDO2 — Authentication
# ─────────────────────────────────────────────────────────────

@app.route("/fido2/auth/begin", methods=["POST"])
@limiter.limit("10 per minute")
def fido2_auth_begin():
    data     = request.get_json(silent=True)
    username = (data or {}).get("username", "").strip()

    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400

    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    credentials = get_credentials_for_user(creds_collection, username)
    if not credentials:
        return jsonify({"success": False, "message": "No passkey registered. Please register one first."}), 400

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=c["credential_id"])
        for c in credentials
    ]

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    save_challenge(username, options.challenge)

    return app.response_class(
        response=webauthn.options_to_json(options),
        mimetype="application/json"
    )


@app.route("/fido2/auth/complete", methods=["POST"])
@limiter.limit("10 per minute")
def fido2_auth_complete():
    data     = request.get_json(silent=True)
    username = (data or {}).get("username", "").strip()
    ip       = get_client_ip()

    if not username or not data:
        return jsonify({"success": False, "message": "Invalid request"}), 400

    challenge = get_challenge(username)
    if not challenge:
        return jsonify({"success": False, "message": "Challenge expired — try again"}), 400

    credential_id_raw = data.get("rawId") or data.get("id")
    if not credential_id_raw:
        return jsonify({"success": False, "message": "Missing credential ID"}), 400

    try:
        padded              = credential_id_raw + "=" * (-len(credential_id_raw) % 4)
        credential_id_bytes = base64.urlsafe_b64decode(padded)
    except Exception:
        return jsonify({"success": False, "message": "Invalid credential ID format"}), 400

    stored = get_credential_by_id(creds_collection, credential_id_bytes)
    if not stored:
        return jsonify({"success": False, "message": "Passkey not recognised"}), 400

    # ── Risk engine (lighter check for FIDO2 — already phishing resistant) ──
    user = users_collection.find_one({"username": username})
    if user:
        risk = calculate_risk(user, ip, users_collection, audit_collection)
        if risk["action"] == "block":
            log_event(audit_collection, LOGIN_FAILURE,
                      username=username, ip=ip,
                      auth_method="fido2", success=False,
                      detail=f"Risk blocked — score {risk['score']} signals: {risk['signals']}")
            return jsonify({
                "success": False,
                "message": "Login blocked due to suspicious activity. Please try again later.",
                "risk_level": risk["level"]
            }), 403

    try:
        verification = webauthn.verify_authentication_response(
            credential=data,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=APP_ORIGIN,
            credential_public_key=stored["public_key"],
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        log_event(audit_collection, LOGIN_FAILURE,
                  username=username, ip=ip,
                  auth_method="fido2", success=False,
                  detail=str(e))
        return jsonify({"success": False, "message": f"Verification failed: {str(e)}"}), 400

    update_sign_count(creds_collection, credential_id_bytes, verification.new_sign_count)
    update_known_ips(users_collection, username, ip)

    risk_detail = f"risk:{risk['level']} score:{risk['score']}" if user else "risk:unknown"
    log_event(audit_collection, LOGIN_SUCCESS,
              username=username, ip=ip,
              auth_method="fido2", success=True,
              detail=risk_detail)

    token    = issue_jwt(username, auth_method="fido2")
    response = make_response(jsonify({"success": True, "message": "Passkey login successful"}))
    response.set_cookie(
        "auth_token", token,
        httponly=True, samesite="Lax",
        secure=IS_PRODUCTION,
        max_age=JWT_EXPIRY_MINS * 60
    )
    return response


# ─────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION)