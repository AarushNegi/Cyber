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
    redirect
)

from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from jose import jwt, JWTError
from dotenv import load_dotenv

import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)
from webauthn.helpers.exceptions import InvalidCBORData
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,   # ← add this
)

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

MONGO_URI       = os.getenv("MONGO_URI",           "mongodb://localhost:27017/")
JWT_SECRET      = os.getenv("JWT_SECRET",           "change-this-secret")
FLASK_SECRET    = os.getenv("FLASK_SECRET_KEY",     "change-this-secret")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRY_MINS = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))
APP_ORIGIN      = os.getenv("APP_ORIGIN",           "http://localhost:5000")
IS_PRODUCTION   = os.getenv("FLASK_ENV", "development") == "production"

# FIDO2 config — RP = Relying Party (your server)
RP_ID   = os.getenv("RP_ID",   "localhost")        # domain only, no http://
RP_NAME = os.getenv("RP_NAME", "ZeroKey Auth")


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
# MongoDB
# ─────────────────────────────────────────────────────────────

client              = MongoClient(MONGO_URI)
database            = client["users"]
users_collection    = database["mails"]
creds_collection    = database["fido2_credentials"]   # ← new


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
    token = request.cookies.get("auth_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


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
    if not user:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    try:
        valid = verify_password(password, user["password"])
    except Exception:
        return jsonify({"success": False, "message": "Auth error — please re-register"}), 500

    if not valid:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    session["username"] = username
    token    = issue_jwt(username)
    response = make_response(jsonify({"success": True, "message": "Login successful"}))
    response.set_cookie(
        "auth_token", token,
        httponly=True, samesite="Lax",
        secure=IS_PRODUCTION,
        max_age=JWT_EXPIRY_MINS * 60
    )
    return response


# ─────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────

@app.route("/logout", methods=["POST"])
def logout():
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
    user = users_collection.find_one({"username": username}, {"_id": 0, "password": 0})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Also tell the dashboard how many passkeys this user has registered
    passkey_count = creds_collection.count_documents({"username": username})

    return jsonify({
        "success":       True,
        "username":      user.get("username"),
        "full_name":     user.get("full_name"),
        "mobile":        user.get("mobile"),
        "dob":           user.get("dob"),
        "created_at":    str(user.get("created_at")),
        "passkey_count": passkey_count          # ← dashboard uses this
    })


# ─────────────────────────────────────────────────────────────
# FIDO2 — Registration
#
# Flow:
#   1. User is logged in with password, sees "Register passkey" on dashboard
#   2. POST /fido2/register/begin   → server sends options to browser
#   3. Browser asks OS for fingerprint/face, signs the challenge
#   4. POST /fido2/register/complete → server verifies + saves public key
# ─────────────────────────────────────────────────────────────

@app.route("/fido2/register/begin", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
def fido2_register_begin():
    username = request.current_user

    # Get existing credentials so the browser won't re-register the same device
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

    # Store challenge — browser must return this exact value signed
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

    if not data:
        return jsonify({"success": False, "message": "No data received"}), 400

    # Retrieve the stored challenge (single-use — deleted on retrieval)
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
        return jsonify({"success": False, "message": f"Verification failed: {str(e)}"}), 400

    # Save public key to MongoDB
    save_credential(creds_collection, username, verification)

    return jsonify({"success": True, "message": "Passkey registered successfully"})


# ─────────────────────────────────────────────────────────────
# FIDO2 — Passkey Management (Stage 4)
# ─────────────────────────────────────────────────────────────

@app.route("/fido2/credentials", methods=["GET"])
@jwt_required()
def list_credentials():
    """Return all passkeys for the logged-in user."""
    username = request.current_user
    creds    = get_credentials_for_user(creds_collection, username)
    result   = []
    for c in creds:
        result.append({
            "id":          c["credential_id"].hex() if isinstance(c["credential_id"], bytes) else str(c["credential_id"]),
            "device_name": c.get("device_name", "My device"),
            "created_at":  str(c.get("created_at", "")),
            "last_used_at":str(c.get("last_used_at", "")),
        })
    return jsonify({"success": True, "credentials": result})


@app.route("/fido2/credential/<cred_id>", methods=["DELETE"])
@jwt_required()
def delete_credential_route(cred_id):
    """Delete a passkey by its hex ID. Safety: cannot delete last passkey."""
    username = request.current_user
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
    return jsonify({"success": True, "message": "Passkey deleted"})


@app.route("/fido2/credential/<cred_id>/rename", methods=["PATCH"])
@jwt_required()
def rename_credential(cred_id):
    """Rename a passkey device label."""
    username = request.current_user
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
    return jsonify({"success": True, "message": "Passkey renamed"})


# ─────────────────────────────────────────────────────────────
# FIDO2 — Authentication (Login)
#
# Flow:
#   1. User types username → clicks "Use Passkey"
#   2. POST /fido2/auth/begin   → server sends challenge + allowed credentials
#   3. Browser asks Windows Hello / fingerprint to sign the challenge
#   4. POST /fido2/auth/complete → server verifies signature → issues JWT
# ─────────────────────────────────────────────────────────────

@app.route("/fido2/auth/begin", methods=["POST"])
@limiter.limit("10 per minute")
def fido2_auth_begin():
    data     = request.get_json(silent=True)
    username = (data or {}).get("username", "").strip()

    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400

    # Check user exists
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Get all passkeys registered by this user
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

    # Store challenge keyed to username
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

    if not username or not data:
        return jsonify({"success": False, "message": "Invalid request"}), 400

    # Retrieve single-use challenge
    challenge = get_challenge(username)
    if not challenge:
        return jsonify({"success": False, "message": "Challenge expired — try again"}), 400

    # Find the credential being used by its ID
    
    credential_id_raw = data.get("rawId") or data.get("id")
    if not credential_id_raw:
        return jsonify({"success": False, "message": "Missing credential ID"}), 400

    try:
        padded = credential_id_raw + "=" * (-len(credential_id_raw) % 4)
        credential_id_bytes = base64.urlsafe_b64decode(padded)
    except Exception:
        return jsonify({"success": False, "message": "Invalid credential ID format"}), 400

    stored = get_credential_by_id(creds_collection, credential_id_bytes)
    if not stored:
        return jsonify({"success": False, "message": "Passkey not recognised"}), 400

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
        return jsonify({"success": False, "message": f"Verification failed: {str(e)}"}), 400

    # Update sign count (replay attack protection)
    update_sign_count(creds_collection, credential_id_bytes, verification.new_sign_count)

    # Issue JWT — same as password login
    token    = issue_jwt(username)
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