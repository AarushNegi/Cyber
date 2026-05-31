"""
setup_db.py

Run this ONCE before starting Stage 2:
    python setup_db.py

Creates the indexes needed for fast FIDO2 credential lookups.
Safe to run multiple times — MongoDB ignores indexes that already exist.
"""

from pymongo import MongoClient, ASCENDING
from dotenv import load_dotenv
import os

load_dotenv()

client     = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
database   = client["users"]

# ── users.mails (existing collection) ────────────────────────
users = database["mails"]
users.create_index([("username", ASCENDING)], unique=True)
print("✓ users.mails  →  index on username")

# ── users.fido2_credentials (new collection) ─────────────────
creds = database["fido2_credentials"]

# Fast lookup by credential_id during authentication
creds.create_index([("credential_id", ASCENDING)], unique=True)
print("✓ fido2_credentials  →  unique index on credential_id")

# Fast lookup of all passkeys for a user (used in auth/begin)
creds.create_index([("username", ASCENDING)])
print("✓ fido2_credentials  →  index on username")

print("\nDone. Your MongoDB is ready for Stage 2.")