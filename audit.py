# audit.py — structured auth event logging for ZeroKey
from datetime import datetime, timezone

# ── Event type constants ──────────────────────────────────────
LOGIN_SUCCESS       = "login_success"
LOGIN_FAILURE       = "login_failure"
LOGOUT              = "logout"
SIGNUP              = "signup"
PASSKEY_REGISTERED  = "passkey_registered"
PASSKEY_DELETED     = "passkey_deleted"
PASSKEY_RENAMED     = "passkey_renamed"
GOOGLE_LOGIN        = "google_login"
GOOGLE_SIGNUP       = "google_signup"

def log_event(audit_collection, event_type, username=None,
              ip=None, auth_method=None, success=True, detail=None):
    """
    Write one audit log entry to MongoDB.

    Fields:
      event_type  — one of the constants above
      username    — who did it (None if unknown, e.g. failed login with bad username)
      ip          — client IP address
      auth_method — "password" | "fido2" | "google" | None
      success     — True / False
      detail      — optional string for failure reason or extra context
      timestamp   — UTC now
    """
    entry = {
        "event_type":   event_type,
        "username":     username,
        "ip":           ip,
        "auth_method":  auth_method,
        "success":      success,
        "detail":       detail,
        "timestamp":    datetime.now(timezone.utc),
    }
    try:
        audit_collection.insert_one(entry)
    except Exception as e:
        # Never let logging crash the app
        print(f"[AUDIT LOG ERROR] {e}")