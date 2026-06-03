# risk.py — Login risk scoring engine for ZeroKey
#
# Scores every login attempt 0-100.
# Low (0-30)    → allow normally
# Medium (31-60) → allow but flag in audit log
# High (61-100)  → block, force passkey step-up
#
# Signals checked:
#   +30  New IP never seen before for this user
#   +20  Unusual hour (midnight–5am local)
#   +25  Multiple recent failures (3+ in last hour)
#   +25  Account was locked recently (unlocked in last 30 min)

from datetime import datetime, timezone, timedelta

# ── Thresholds ────────────────────────────────────────────────
RISK_LOW    = 30
RISK_HIGH   = 61

# ── Signal weights ────────────────────────────────────────────
WEIGHT_NEW_IP       = 30
WEIGHT_UNUSUAL_HOUR = 20
WEIGHT_RECENT_FAILS = 25
WEIGHT_RECENT_LOCK  = 25


def calculate_risk(user: dict, ip: str, users_collection, audit_collection) -> dict:
    """
    Calculate risk score for a login attempt.

    Returns:
    {
        "score":   int (0-100),
        "level":   "low" | "medium" | "high",
        "signals": [list of triggered signal names],
        "action":  "allow" | "flag" | "block"
    }
    """
    score   = 0
    signals = []
    now     = datetime.now(timezone.utc)

    # ── Signal 1: New IP ─────────────────────────────────────
    known_ips = user.get("known_ips", [])
    if ip not in known_ips:
        score += WEIGHT_NEW_IP
        signals.append("new_ip")

    # ── Signal 2: Unusual hour (midnight–5am UTC) ────────────
    if now.hour < 5:
        score += WEIGHT_UNUSUAL_HOUR
        signals.append("unusual_hour")

    # ── Signal 3: Recent failures (3+ in last hour) ──────────
    one_hour_ago = now - timedelta(hours=1)
    recent_fails = audit_collection.count_documents({
        "username":   user.get("username"),
        "event_type": "login_failure",
        "timestamp":  {"$gte": one_hour_ago},
    })
    if recent_fails >= 3:
        score += WEIGHT_RECENT_FAILS
        signals.append("recent_failures")

    # ── Signal 4: Account was locked recently ────────────────
    locked_until = user.get("locked_until")
    if locked_until:
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        unlocked_recently = (now - locked_until) < timedelta(minutes=30)
        if unlocked_recently:
            score += WEIGHT_RECENT_LOCK
            signals.append("recently_locked")

    # ── Cap at 100 ───────────────────────────────────────────
    score = min(score, 100)

    # ── Level + action ───────────────────────────────────────
    if score <= RISK_LOW:
        level  = "low"
        action = "allow"
    elif score <= RISK_HIGH:
        level  = "medium"
        action = "flag"
    else:
        level  = "high"
        action = "block"

    return {
        "score":   score,
        "level":   level,
        "signals": signals,
        "action":  action,
    }


def update_known_ips(users_collection, username: str, ip: str) -> None:
    """
    Add IP to user's known_ips list (max 20 stored).
    Called after every successful login.
    """
    users_collection.update_one(
        {"username": username},
        {
            "$addToSet": {"known_ips": ip},
        }
    )
    # Keep only last 20 known IPs
    user = users_collection.find_one({"username": username}, {"known_ips": 1})
    if user and len(user.get("known_ips", [])) > 20:
        users_collection.update_one(
            {"username": username},
            {"$set": {"known_ips": user["known_ips"][-20:]}}
        )