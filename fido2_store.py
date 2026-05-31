"""
fido2_store.py

Two responsibilities:
  1. Challenge store  — temporarily holds FIDO2 challenges while the
                        browser is completing registration or login.
                        Uses an in-memory TTL cache (no Redis needed locally).
                        Each challenge expires after 120 seconds automatically.

  2. Credential store — helper functions for reading/writing FIDO2
                        credentials in MongoDB.

MongoDB collection: fido2_credentials
One document per registered passkey. A single user can have multiple
documents (one per device/YubiKey).

Document shape:
{
    "username":       "aarush",          # links to users.mails collection
    "credential_id":  "<base64url>",     # unique ID issued by the device
    "public_key":     "<bytes>",         # stored as Binary in MongoDB
    "sign_count":     0,                 # increments every login (replay protection)
    "aaguid":         "<uuid string>",   # identifies the authenticator model
    "device_name":    "iPhone Touch ID", # friendly label (user can rename)
    "created_at":     datetime,
    "last_used_at":   datetime
}
"""

from datetime import datetime, timezone
from cachetools import TTLCache
import threading


# ─────────────────────────────────────────────────────────────
# In-memory challenge store
# TTLCache: max 500 challenges at a time, each expires after 120 seconds.
# Thread-safe via a lock (Flask handles requests concurrently).
# ─────────────────────────────────────────────────────────────

_cache      = TTLCache(maxsize=500, ttl=120)
_cache_lock = threading.Lock()


def save_challenge(username: str, challenge: bytes) -> None:
    """Store a challenge for a user. Overwrites any existing one."""
    with _cache_lock:
        _cache[f"challenge:{username}"] = challenge


def get_challenge(username: str) -> bytes | None:
    """
    Retrieve and IMMEDIATELY DELETE the challenge for a user.
    Challenges are single-use — call this once during verification.
    Returns None if expired or never set.
    """
    with _cache_lock:
        return _cache.pop(f"challenge:{username}", None)


# ─────────────────────────────────────────────────────────────
# MongoDB credential helpers
# These are called from app.py — pass in the collection object.
# ─────────────────────────────────────────────────────────────

def save_credential(collection, username: str, verification) -> None:
    """
    Save a verified FIDO2 credential to MongoDB after successful registration.
    `verification` is the object returned by webauthn.verify_registration_response().
    """
    collection.insert_one({
        "username":      username,
        "credential_id": verification.credential_id,        # bytes
        "public_key":    verification.credential_public_key,# bytes
        "sign_count":    verification.sign_count,
        "aaguid":        str(verification.aaguid),
        "device_name":   "My device",                       # user can rename later
        "created_at":    datetime.now(timezone.utc),
        "last_used_at":  datetime.now(timezone.utc),
    })


def get_credentials_for_user(collection, username: str) -> list:
    """
    Return all registered passkeys for a user.
    Used in /fido2/auth/begin to tell the browser which credentials to try.
    """
    return list(collection.find({"username": username}))


def get_credential_by_id(collection, credential_id: bytes):
    """
    Find a single credential by its ID.
    Used in /fido2/auth/complete to look up the stored public key.
    """
    return collection.find_one({"credential_id": credential_id})


def update_sign_count(collection, credential_id: bytes, new_count: int) -> None:
    """
    Update the sign count after a successful login.
    If the new count is not higher than stored, something is wrong
    (possible cloned credential) — this is checked in app.py before calling here.
    """
    collection.update_one(
        {"credential_id": credential_id},
        {
            "$set": {
                "sign_count":   new_count,
                "last_used_at": datetime.now(timezone.utc),
            }
        }
    )


def delete_credential(collection, credential_id: bytes, username: str) -> bool:
    """
    Remove a specific passkey for a user.
    Returns True if something was deleted, False if not found.
    Used later when user wants to remove a device from their account.
    """
    result = collection.delete_one({
        "credential_id": credential_id,
        "username":       username,      # safety: can only delete own credentials
    })
    return result.deleted_count > 0