import base64
import datetime
import functools
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import uuid

import dotenv
import flask
import webauthn
import webauthn.helpers
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import g
from PIL import Image, UnidentifiedImageError

import db
import mailer
import totp
from legacy_migration import migrate_legacy_files

dotenv.load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("SERES_DATA_DIR", BASE_DIR)
USER_DATA = os.path.join(DATA_DIR, "user_data")
CHATS = os.path.join(DATA_DIR, "chats")
DB = os.path.join(DATA_DIR, "users.db")

SESSION_COOKIE = "sessioncookie"
CONSENT_COOKIE = "cookie_consent"
SESSION_DAYS = 90
DEFAULT_KDF_ITERATIONS = 600_000
MIN_KDF_ITERATIONS = 100_000
MAX_KDF_ITERATIONS = 5_000_000
MAX_GROUP_MEMBERS = 50
MAX_CIPHERTEXT_LEN = 64 * 1024
MAX_AVATAR_BYTES = 2 * 1024 * 1024
# Encrypted attachments (images, files, voice messages). AES-GCM adds 16 bytes.
MAX_FILE_BYTES = 16 * 1024 * 1024 + 1024
MAX_FILES_PER_MESSAGE = 10
FILES = os.path.join(DATA_DIR, "files")
# Allowed timers for disappearing messages (seconds), 0 = off.
DISAPPEAR_OPTIONS = (0, 3600, 86400, 7 * 86400, 90 * 86400)
MAX_PINS = 50
ONLINE_SECONDS = 45

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")

app = flask.Flask(__name__, static_folder="../public", static_url_path="/")
app.config["DEBUG"] = False
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + 64 * 1024
ph = PasswordHasher(time_cost=4)
# Used to keep login timing the same for unknown users.
DUMMY_HASH = ph.hash(secrets.token_hex(16))


# --------------------------------------------------------------------------
# Infrastructure
# --------------------------------------------------------------------------


def get_db():
    if "db" not in g:
        g.db = db.connect(DB)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app():
    os.makedirs(USER_DATA, exist_ok=True)
    os.makedirs(FILES, exist_ok=True)
    conn = db.connect(DB)
    try:
        db.init_schema(conn)
        migrate_legacy_files(conn, USER_DATA, CHATS)
        db.server_secret(conn)
    finally:
        conn.close()


def start_heartbeat():
    url = os.getenv("URL")
    if not url:
        return
    try:
        import pyheartbeat

        pyheartbeat.setUrl(url)
        pyheartbeat.heartbeat(interval=600, name="uptime-checker")
    except Exception as e:  # monitoring must never take the chat down
        print("heartbeat disabled:", e)


class RateLimiter:
    """Small in-memory sliding window limiter (per process)."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def hit(self, key, limit, window):
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 50_000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 3600}
            return allowed


limiter = RateLimiter()


def rate_limited(key, limit, window):
    if app.config.get("TESTING_DISABLE_RATE_LIMIT"):
        return False
    return not limiter.hit(key, limit, window)


def client_ip():
    """The visitor's IP for rate limits. Behind a Cloudflare tunnel or a reverse
    proxy on this server every request comes from localhost, so then the
    address the proxy passes on is used. Only trusted from localhost, so
    nobody can choose their own IP with a header."""
    remote = flask.request.remote_addr or "?"
    try:
        local = ipaddress.ip_address(remote).is_loopback
    except ValueError:
        local = False
    if local:
        headers = flask.request.headers
        forwarded = headers.get("CF-Connecting-IP") or headers.get("X-Real-IP")
        if not forwarded and headers.get("X-Forwarded-For"):
            # The last entry is the one the proxy itself added.
            forwarded = headers["X-Forwarded-For"].split(",")[-1]
        if forwarded and forwarded.strip():
            return forwarded.strip()[:64]
    return remote


def error(message, status=400):
    return {"message": message, "success": False}, status


def ok(**data):
    return {"success": True, **data}, 200


def json_body():
    data = flask.request.get_json(silent=True)
    if not isinstance(data, dict):
        flask.abort(flask.make_response(error("Expected a JSON object")))
    return data


def str_field(data, name, max_len=256, required=True):
    value = data.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > max_len:
        flask.abort(flask.make_response(error(f"Missing or invalid '{name}'")))
    return value


def b64_field(data, name, max_len=8192):
    value = str_field(data, name, max_len)
    if not B64_RE.match(value):
        flask.abort(flask.make_response(error(f"Invalid encoding of '{name}'")))
    return value


@app.before_request
def csrf_protect():
    if flask.request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    origin = flask.request.headers.get("Origin")
    if origin:
        # Compare hosts only, so TLS terminating reverse proxies keep working.
        allowed = {flask.request.host, flask.request.headers.get("X-Forwarded-Host")}
        allowed.update(h.strip() for h in os.getenv("SERES_ALLOWED_HOSTS", "").split(",") if h.strip())
        if urllib.parse.urlsplit(origin).netloc not in allowed:
            return error("Cross-site request rejected", 403)
    return None


@app.after_request
def security_headers(response):
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; media-src 'self' blob:; object-src 'self'; "
        "frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(self), geolocation=()")
    if flask.request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    if flask.request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


# --------------------------------------------------------------------------
# Sessions & users
# --------------------------------------------------------------------------


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    conn = get_db()
    conn.execute(
        "INSERT INTO user_sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?), ?)",
        (hash_token(token), user_id, f"+{SESSION_DAYS} days", db.now_iso()),
    )
    conn.commit()
    return token


def cookies_accepted():
    return flask.request.cookies.get(CONSENT_COOKIE) == "accepted"


def set_session_cookie(response, token, persistent=None):
    """Without cookie consent the login only lasts until the browser is closed."""
    if persistent is None:
        persistent = cookies_accepted()
    secure = flask.request.is_secure or flask.request.headers.get("X-Forwarded-Proto") == "https"
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_DAYS * 24 * 3600 if persistent else None,
        httponly=True,
        secure=secure,
        samesite="Strict",
        path="/",
    )
    # The old frontend stored the username in a readable cookie; remove it.
    response.delete_cookie("username", path="/")


def current_user():
    if "user" in g:
        return g.user
    g.user = None
    token = flask.request.cookies.get(SESSION_COOKIE)
    if token:
        row = (
            get_db()
            .execute(
                """SELECT u.* FROM user_sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ?""",
                (hash_token(token), db.now_iso()),
            )
            .fetchone()
        )
        g.user = row
        if row is not None:
            touch_last_seen(row)
    return g.user


def touch_last_seen(user):
    """Remembers the last activity for "online" / "last seen" (at most every 20 seconds)."""
    now = db.now_iso()
    last = user["last_seen"]
    if last and seconds_between(last, now) < 20:
        return
    conn = get_db()
    conn.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, user["id"]))
    conn.commit()


def parse_iso(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def seconds_between(earlier, later):
    try:
        return (parse_iso(later) - parse_iso(earlier)).total_seconds()
    except (TypeError, ValueError):
        return float("inf")


def iso_in(seconds):
    moment = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def presence(viewer, other):
    """Online state / last seen, only if both people share it (like WhatsApp)."""
    if not other or not viewer["show_last_seen"] or not other["show_last_seen"] or not other["last_seen"]:
        return None
    return {
        "online": seconds_between(other["last_seen"], db.now_iso()) < ONLINE_SECONDS,
        "last_seen": other["last_seen"],
    }


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return error("Not logged in", 401)
        return view(*args, **kwargs)

    return wrapper


def find_user_by_name(username):
    if not isinstance(username, str) or not username.strip():
        return None
    return (
        get_db()
        .execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),))
        .fetchone()
    )


def find_user_by_login(nameomail):
    conn = get_db()
    if "@" in nameomail:
        return conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (nameomail,)
        ).fetchone()
    return conn.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (nameomail,)
    ).fetchone()


def display_name(row):
    """The name shown in the app: the display name, or the username without one."""
    keys = row.keys() if hasattr(row, "keys") else ()
    return (row["display_name"] if "display_name" in keys else None) or row["username"]


def public_user(row):
    return {"id": row["id"], "username": row["username"], "display_name": display_name(row)}


def own_user(row):
    return {
        **public_user(row),
        "email": row["email"],
        "pub_ecdh": row["pub_ecdh"],
        "pub_sign": row["pub_sign"],
        "enc_private": row["enc_private"],
        "show_last_seen": bool(row["show_last_seen"]),
    }


def fake_salt(identifier):
    secret = db.server_secret(get_db())
    digest = hmac.new(secret.encode(), identifier.lower().encode(), hashlib.sha256).digest()
    return base64.b64encode(digest[:16]).decode()


def verify_hash(stored, candidate):
    try:
        return ph.verify(stored or DUMMY_HASH, candidate) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_key_bundle(data):
    keys = data.get("keys")
    if not isinstance(keys, dict):
        flask.abort(flask.make_response(error("Missing encryption keys")))
    return {
        "pub_ecdh": b64_field(keys, "pub_ecdh", 512),
        "pub_sign": b64_field(keys, "pub_sign", 512),
        "enc_private": str_field(keys, "enc_private", 8192),
    }


def validate_kdf(data):
    salt = b64_field(data, "kdf_salt", 64)
    iterations = data.get("kdf_iterations")
    if not isinstance(iterations, int) or not MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS:
        flask.abort(flask.make_response(error("Invalid kdf_iterations")))
    return salt, iterations


# --------------------------------------------------------------------------
# Pages & auth
# --------------------------------------------------------------------------


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/online", methods=["GET", "POST"])
def online():
    return {"message": "im up", "success": True}, 200


@app.route("/api/prelogin", methods=["POST"])
def prelogin():
    data = json_body()
    nameomail = str_field(data, "nameomail", 254).strip()
    if rate_limited(("prelogin", client_ip()), 60, 60):
        return error("Too many attempts, please wait a minute", 429)
    user = find_user_by_login(nameomail)
    if user is None:
        return ok(kdf_salt=fake_salt(nameomail), kdf_iterations=DEFAULT_KDF_ITERATIONS, legacy=False)
    if user["auth_version"] == 0 and not user["kdf_salt"]:
        conn = get_db()
        conn.execute(
            "UPDATE users SET kdf_salt = ?, kdf_iterations = ? WHERE id = ?",
            (base64.b64encode(secrets.token_bytes(16)).decode(), DEFAULT_KDF_ITERATIONS, user["id"]),
        )
        conn.commit()
        user = find_user_by_login(nameomail)
    return ok(
        kdf_salt=user["kdf_salt"],
        kdf_iterations=user["kdf_iterations"] or DEFAULT_KDF_ITERATIONS,
        legacy=user["auth_version"] == 0,
    )


@app.route("/api/register", methods=["POST"])
def register():
    data = json_body()
    username = str_field(data, "username", 64).strip()
    email = str_field(data, "email", 254).strip()
    auth_hash = b64_field(data, "auth_hash", 128)
    kdf_salt, kdf_iterations = validate_kdf(data)
    keys = validate_key_bundle(data)

    if rate_limited(("register", client_ip()), 10, 3600):
        return error("Too many registrations, please try again later", 429)
    if not USERNAME_RE.match(username):
        return error("Username must be 3-20 characters: letters, numbers, '_' or '-'")
    if not EMAIL_RE.match(email):
        return error("Email is invalid")

    conn = get_db()
    if find_user_by_name(username):
        return error("Username already taken")
    if conn.execute("SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone():
        return error("Email already in use")

    conn.execute(
        """INSERT INTO users (id, email, username, passwd, auth_version, kdf_salt, kdf_iterations,
                              pub_ecdh, pub_sign, enc_private, created_at)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()),
            email,
            username,
            ph.hash(auth_hash),
            kdf_salt,
            kdf_iterations,
            keys["pub_ecdh"],
            keys["pub_sign"],
            keys["enc_private"],
            db.now_iso(),
        ),
    )
    conn.commit()
    return {"message": "User created successfully!", "success": True}, 200


@app.route("/api/login", methods=["POST"])
def login():
    data = json_body()
    nameomail = str_field(data, "nameomail", 254).strip()
    auth_hash = b64_field(data, "auth_hash", 128)

    if rate_limited(("login-ip", client_ip()), 60, 60) or rate_limited(
        ("login-account", nameomail.lower()), 10, 300
    ):
        return error("Too many login attempts, please wait a few minutes", 429)

    user = find_user_by_login(nameomail)
    conn = get_db()

    if user is not None and user["auth_version"] == 0:
        # Account from before end-to-end encryption: check the old password once,
        # then switch it to the client derived hash and store the new key bundle.
        legacy_password = data.get("passwd")
        if not isinstance(legacy_password, str) or not verify_hash(user["passwd"], legacy_password):
            return error("Login not succesfull")
        keys = validate_key_bundle(data)
        if not user["kdf_salt"]:
            return error("Please retry the login")
        conn.execute(
            """UPDATE users SET passwd = ?, auth_version = 1, pub_ecdh = ?, pub_sign = ?, enc_private = ?
               WHERE id = ?""",
            (ph.hash(auth_hash), keys["pub_ecdh"], keys["pub_sign"], keys["enc_private"], user["id"]),
        )
        conn.commit()
    elif user is None or not verify_hash(user["passwd"], auth_hash):
        if user is None:
            verify_hash(None, auth_hash)
        return error("Login not succesfull")

    methods = twofa_methods(user)
    if methods:
        # Password is right, but the second factor is still missing: no session yet,
        # and the encrypted keys are only handed out after the second step.
        token = new_challenge(conn, user["id"], "login")
        conn.commit()
        return ok(two_factor={"token": token, "methods": methods, "backup_codes": has_backup_codes(user["id"])})
    return login_response(user["id"])


def has_backup_codes(user_id):
    return (
        get_db()
        .execute("SELECT 1 FROM recovery_codes WHERE user_id = ? AND used_at IS NULL", (user_id,))
        .fetchone()
        is not None
    )


def login_response(user_id):
    """Starts a session and returns what the client needs to unlock its keys."""
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    response = flask.make_response(
        {
            "message": "Login succesfull!",
            "success": True,
            "user": own_user(user),
            "enc_private": user["enc_private"],
        }
    )
    set_session_cookie(response, create_session(user["id"]))
    return response, 200


@app.route("/api/logout", methods=["POST"])
def logout():
    token = flask.request.cookies.get(SESSION_COOKIE)
    if token:
        conn = get_db()
        conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (hash_token(token),))
        conn.commit()
    response = flask.make_response({"message": "Logout succesfull!", "success": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie("username", path="/")
    return response, 200


@app.route("/api/cookie_consent", methods=["POST"])
def cookie_consent():
    accepted = (flask.request.get_json(silent=True) or {}).get("accepted") is True
    response = flask.make_response({"success": True, "accepted": accepted})
    # Remembering the decision itself is necessary, so it is always kept.
    response.set_cookie(
        CONSENT_COOKIE,
        "accepted" if accepted else "denied",
        max_age=365 * 24 * 3600,
        samesite="Lax",
        path="/",
    )
    # Re-issue the login cookie so it matches the new decision.
    token = flask.request.cookies.get(SESSION_COOKIE)
    if token and current_user() is not None:
        set_session_cookie(response, token, persistent=accepted)
    return response, 200


@app.route("/api/auth_cookie", methods=["POST", "GET"])
def auth_session_cookie():
    if current_user() is None:
        return error("Cookie invalid")
    return {"message": "Cookie valid", "success": True}, 200


@app.route("/api/me")
@login_required
def me():
    user = current_user()
    return ok(user=own_user(user))


@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    data = json_body()
    user = current_user()
    old_hash = b64_field(data, "old_auth_hash", 128)
    new_hash = b64_field(data, "auth_hash", 128)
    kdf_salt, kdf_iterations = validate_kdf(data)
    enc_private = str_field(data, "enc_private", 8192)
    if rate_limited(("change-password", user["id"]), 5, 300):
        return error("Too many attempts, please wait a few minutes", 429)
    if not verify_hash(user["passwd"], old_hash):
        return error("Current password is wrong")
    conn = get_db()
    conn.execute(
        "UPDATE users SET passwd = ?, kdf_salt = ?, kdf_iterations = ?, enc_private = ? WHERE id = ?",
        (ph.hash(new_hash), kdf_salt, kdf_iterations, enc_private, user["id"]),
    )
    token_hash = hash_token(flask.request.cookies.get(SESSION_COOKIE, ""))
    conn.execute(
        "DELETE FROM user_sessions WHERE user_id = ? AND token_hash != ?", (user["id"], token_hash)
    )
    conn.commit()
    return {"message": "Password changed", "success": True}, 200


# --------------------------------------------------------------------------
# Backup codes
# --------------------------------------------------------------------------

RECOVERY_CODE_COUNT = 10
# The public first part of a code, e.g. "K7QF" of "K7QF-2M9X-HP4C-ZT8B".
SLOT_RE = re.compile(r"^[A-HJ-NP-Z2-9]{4}$")


def validate_recovery_codes(data):
    codes = data.get("codes")
    if not isinstance(codes, list) or len(codes) != RECOVERY_CODE_COUNT:
        flask.abort(flask.make_response(error(f"Exactly {RECOVERY_CODE_COUNT} codes are needed")))
    result = []
    for code in codes:
        if not isinstance(code, dict):
            flask.abort(flask.make_response(error("Invalid code")))
        slot = code.get("slot")
        if not isinstance(slot, str) or not SLOT_RE.match(slot):
            flask.abort(flask.make_response(error("Invalid code slot")))
        result.append(
            {
                "slot": slot,
                "kdf_salt": b64_field(code, "kdf_salt", 64),
                "auth_hash": b64_field(code, "auth_hash", 128),
                "enc_private": str_field(code, "enc_private", 8192),
            }
        )
    if len({c["slot"] for c in result}) != len(result):
        flask.abort(flask.make_response(error("Code slots must be different")))
    return result


@app.route("/api/recovery/codes")
@login_required
def recovery_status():
    """How many backup codes are left. The codes themselves are never shown again."""
    row = (
        get_db()
        .execute(
            """SELECT COUNT(*) AS total, SUM(used_at IS NULL) AS unused, MAX(created_at) AS created_at
               FROM recovery_codes WHERE user_id = ?""",
            (current_user()["id"],),
        )
        .fetchone()
    )
    return ok(total=row["total"], unused=row["unused"] or 0, created_at=row["created_at"])


@app.route("/api/recovery/codes", methods=["POST"])
@login_required
def replace_recovery_codes():
    """Stores 10 new backup codes (made in the browser); all old codes stop working."""
    user = current_user()
    data = json_body()
    old_hash = b64_field(data, "old_auth_hash", 128)
    codes = validate_recovery_codes(data)
    if rate_limited(("recovery-codes", user["id"]), 5, 300):
        return error("Too many attempts, please wait a few minutes", 429)
    if not verify_hash(user["passwd"], old_hash):
        return error("Password is wrong")
    conn = get_db()
    now = db.now_iso()
    with db.write_transaction(conn):
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
        for code in codes:
            conn.execute(
                """INSERT INTO recovery_codes (user_id, slot, kdf_salt, auth_hash, enc_private, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user["id"], code["slot"], code["kdf_salt"], ph.hash(code["auth_hash"]), code["enc_private"], now),
            )
    return ok(total=len(codes), unused=len(codes), created_at=now)


def find_recovery_code(data):
    """The user and unused code addressed by a request (or None, None)."""
    nameomail = str_field(data, "nameomail", 254).strip()
    slot = str_field(data, "slot", 8).strip().upper()
    user = find_user_by_login(nameomail)
    if user is None or not SLOT_RE.match(slot):
        return None, None
    code = (
        get_db()
        .execute(
            "SELECT * FROM recovery_codes WHERE user_id = ? AND slot = ? AND used_at IS NULL",
            (user["id"], slot),
        )
        .fetchone()
    )
    return (user, code) if code else (None, None)


def recovery_rate_limited(data):
    account = str(data.get("nameomail", "")).strip().lower()
    return rate_limited(("recovery-ip", client_ip()), 20, 900) or rate_limited(
        ("recovery-account", account), 10, 900
    )


@app.route("/api/recovery/prelogin", methods=["POST"])
def recovery_prelogin():
    """Salt of a backup code. Unknown accounts/codes get a stable fake salt."""
    data = json_body()
    if recovery_rate_limited(data):
        return error("Too many attempts, please wait a few minutes", 429)
    _, code = find_recovery_code(data)
    if code is None:
        fake = fake_salt("recovery|" + str(data.get("nameomail", "")) + "|" + str(data.get("slot", "")))
        return ok(kdf_salt=fake)
    return ok(kdf_salt=code["kdf_salt"])


def verified_recovery_code(data):
    user, code = find_recovery_code(data)
    auth_hash = b64_field(data, "auth_hash", 128)
    if code is None:
        verify_hash(None, auth_hash)
        return None, None
    if not verify_hash(code["auth_hash"], auth_hash):
        return None, None
    return user, code


@app.route("/api/recovery/unlock", methods=["POST"])
def recovery_unlock():
    """Checks a backup code and returns the keys encrypted with that code."""
    data = json_body()
    if recovery_rate_limited(data):
        return error("Too many attempts, please wait a few minutes", 429)
    user, code = verified_recovery_code(data)
    if code is None:
        return error("Username or backup code is wrong")
    return ok(enc_private=code["enc_private"], pub_ecdh=user["pub_ecdh"], pub_sign=user["pub_sign"])


@app.route("/api/recovery/reset", methods=["POST"])
def recovery_reset():
    """Sets a new password with a backup code. The code can't be used again."""
    data = json_body()
    if recovery_rate_limited(data):
        return error("Too many attempts, please wait a few minutes", 429)
    user, code = verified_recovery_code(data)
    if code is None:
        return error("Username or backup code is wrong")
    new_hash = b64_field(data, "new_auth_hash", 128)
    kdf_salt, kdf_iterations = validate_kdf(data)
    enc_private = str_field(data, "enc_private", 8192)
    conn = get_db()
    with db.write_transaction(conn):
        used = conn.execute(
            "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND slot = ? AND used_at IS NULL",
            (db.now_iso(), user["id"], code["slot"]),
        )
        if used.rowcount == 0:
            flask.abort(flask.make_response(error("Username or backup code is wrong")))
        conn.execute(
            "UPDATE users SET passwd = ?, kdf_salt = ?, kdf_iterations = ?, enc_private = ? WHERE id = ?",
            (ph.hash(new_hash), kdf_salt, kdf_iterations, enc_private, user["id"]),
        )
        # Whoever had the old password is logged out everywhere.
        conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user["id"],))
    return login_response(user["id"])


# --------------------------------------------------------------------------
# Two-factor authentication (optional): passkeys and authenticator apps
# --------------------------------------------------------------------------

TWOFA_LOGIN_MINUTES = 5
TWOFA_MAX_ATTEMPTS = 5


def passkey_rows(user_id):
    return get_db().execute(
        "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at", (user_id,)
    ).fetchall()


def twofa_methods(user):
    """Which second factors the account has; empty = 2FA is off."""
    methods = []
    if passkey_rows(user["id"]):
        methods.append("passkey")
    if user["totp_secret"]:
        methods.append("totp")
    return methods


def require_password(data):
    """2FA changes need the current password, so a stolen session can't lock the owner out."""
    user = current_user()
    old_hash = b64_field(data, "old_auth_hash", 128)
    if rate_limited(("twofa-password", user["id"]), 10, 300):
        flask.abort(flask.make_response(error("Too many attempts, please wait a few minutes", 429)))
    if not verify_hash(user["passwd"], old_hash):
        flask.abort(flask.make_response(error("Password is wrong")))
    return user


@app.route("/api/2fa")
@login_required
def twofa_status():
    user = current_user()
    passkeys = [
        {"id": row["id"], "name": row["name"], "created_at": row["created_at"], "last_used_at": row["last_used_at"]}
        for row in passkey_rows(user["id"])
    ]
    return ok(enabled=bool(twofa_methods(user)), totp=bool(user["totp_secret"]), passkeys=passkeys)


@app.route("/api/2fa/totp/setup", methods=["POST"])
@login_required
def totp_setup():
    """Creates a secret for an authenticator app; active only after a correct code."""
    user = require_password(json_body())
    secret = totp.new_secret()
    conn = get_db()
    conn.execute("UPDATE users SET totp_pending = ? WHERE id = ?", (secret, user["id"]))
    conn.commit()
    return ok(secret=secret, uri=totp.provisioning_uri(secret, user["username"]))


@app.route("/api/2fa/totp/enable", methods=["POST"])
@login_required
def totp_enable():
    user = current_user()
    if rate_limited(("totp-enable", user["id"]), 10, 300):
        return error("Too many attempts, please wait a few minutes", 429)
    step = totp.verify(user["totp_pending"], json_body().get("code"))
    if step is None:
        return error("The code is wrong. Check the time on your phone and try again.")
    conn = get_db()
    conn.execute(
        "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = ? WHERE id = ?",
        (step, user["id"]),
    )
    conn.commit()
    return ok(message="Authenticator app enabled")


@app.route("/api/2fa/totp/disable", methods=["POST"])
@login_required
def totp_disable():
    user = require_password(json_body())
    conn = get_db()
    conn.execute(
        "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = 0 WHERE id = ?", (user["id"],)
    )
    conn.commit()
    return ok(message="Authenticator app removed")


# Passkeys (WebAuthn). The phone, a security key, Windows Hello or Touch ID
# signs a random challenge; the browser offers "use a phone" via QR code.


def webauthn_rp_id():
    """The domain passkeys are bound to (without port)."""
    configured = os.getenv("WEBAUTHN_RP_ID")
    if configured:
        return configured
    if os.getenv("PUBLIC_URL"):
        return urllib.parse.urlsplit(os.getenv("PUBLIC_URL")).hostname
    return flask.request.host.split(":")[0]


def webauthn_origins():
    origins = set()
    if os.getenv("PUBLIC_URL"):
        parts = urllib.parse.urlsplit(os.getenv("PUBLIC_URL"))
        origins.add(f"{parts.scheme}://{parts.netloc}")
    for host in (flask.request.host, flask.request.headers.get("X-Forwarded-Host")):
        if host:
            origins.update({f"https://{host}", f"http://{host}"})
    return sorted(origins)


def new_challenge(conn, user_id, purpose, minutes=TWOFA_LOGIN_MINUTES, challenge=None):
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO twofa_challenges (token_hash, user_id, purpose, challenge, expires_at) VALUES (?, ?, ?, ?, ?)",
        (hash_token(token), user_id, purpose, challenge, iso_in(minutes * 60)),
    )
    # Old, expired challenges are not needed anymore.
    conn.execute("DELETE FROM twofa_challenges WHERE expires_at < ?", (db.now_iso(),))
    return token


def find_challenge(token, purpose):
    if not isinstance(token, str) or len(token) > 100:
        return None
    return (
        get_db()
        .execute(
            "SELECT * FROM twofa_challenges WHERE token_hash = ? AND purpose = ? AND expires_at > ?",
            (hash_token(token), purpose, db.now_iso()),
        )
        .fetchone()
    )


def credential_descriptors(user_id):
    from webauthn.helpers.structs import AuthenticatorTransport, PublicKeyCredentialDescriptor

    descriptors = []
    for row in passkey_rows(user_id):
        transports = []
        for name in json.loads(row["transports"] or "[]"):
            try:
                transports.append(AuthenticatorTransport(name))
            except ValueError:
                # A transport this webauthn version doesn't know: leave it out.
                continue
        descriptors.append(
            PublicKeyCredentialDescriptor(id=webauthn.base64url_to_bytes(row["id"]), transports=transports or None)
        )
    return descriptors


@app.route("/api/2fa/passkeys/options", methods=["POST"])
@login_required
def passkey_register_options():
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    user = require_password(json_body())
    if len(passkey_rows(user["id"])) >= 10:
        return error("You can add at most 10 passkeys")
    options = webauthn.generate_registration_options(
        rp_id=webauthn_rp_id(),
        rp_name="SereS",
        user_id=user["id"].encode(),
        user_name=user["username"],
        user_display_name=display_name(user),
        exclude_credentials=credential_descriptors(user["id"]),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    conn = get_db()
    token = new_challenge(conn, user["id"], "register", challenge=webauthn.helpers.bytes_to_base64url(options.challenge))
    conn.commit()
    return ok(token=token, options=json.loads(webauthn.options_to_json(options)))


@app.route("/api/2fa/passkeys/register", methods=["POST"])
@login_required
def passkey_register():
    user = current_user()
    data = json_body()
    pending = find_challenge(data.get("token"), "register")
    if pending is None or pending["user_id"] != user["id"]:
        return error("The request expired, please try again")
    name = " ".join(str(data.get("name") or "").split())[:40] or "Passkey"
    try:
        verified = webauthn.verify_registration_response(
            credential=data.get("credential"),
            expected_challenge=webauthn.base64url_to_bytes(pending["challenge"]),
            expected_rp_id=webauthn_rp_id(),
            expected_origin=webauthn_origins(),
        )
    except Exception as e:  # invalid or tampered response
        print("passkey registration failed:", e)
        return error("The passkey could not be verified")
    credential_id = webauthn.helpers.bytes_to_base64url(verified.credential_id)
    transports = (data.get("credential") or {}).get("response", {}).get("transports") or []
    conn = get_db()
    conn.execute("DELETE FROM twofa_challenges WHERE token_hash = ?", (pending["token_hash"],))
    try:
        conn.execute(
            """INSERT INTO passkeys (id, user_id, public_key, sign_count, transports, name, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                credential_id,
                user["id"],
                webauthn.helpers.bytes_to_base64url(verified.credential_public_key),
                verified.sign_count,
                json.dumps([t for t in transports if isinstance(t, str)][:8]),
                name,
                db.now_iso(),
            ),
        )
    except sqlite3.IntegrityError:
        return error("This passkey is already registered")
    conn.commit()
    return ok(message="Passkey added")


@app.route("/api/2fa/passkeys/delete", methods=["POST"])
@login_required
def passkey_delete():
    data = json_body()
    user = require_password(data)
    conn = get_db()
    cur = conn.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (str(data.get("id")), user["id"]))
    conn.commit()
    if cur.rowcount == 0:
        return error("Passkey not found", 404)
    return ok(message="Passkey removed")


@app.route("/api/login/2fa/options", methods=["POST"])
def login_passkey_options():
    """Challenge for signing in with a passkey as second factor."""
    pending = find_challenge(json_body().get("token"), "login")
    if pending is None:
        return error("The login expired, please log in again", 401)
    options = webauthn.generate_authentication_options(
        rp_id=webauthn_rp_id(), allow_credentials=credential_descriptors(pending["user_id"])
    )
    conn = get_db()
    conn.execute(
        "UPDATE twofa_challenges SET challenge = ? WHERE token_hash = ?",
        (webauthn.helpers.bytes_to_base64url(options.challenge), pending["token_hash"]),
    )
    conn.commit()
    return ok(options=json.loads(webauthn.options_to_json(options)))


def check_passkey(pending, credential):
    if not pending["challenge"] or not isinstance(credential, dict):
        return False
    row = (
        get_db()
        .execute(
            "SELECT * FROM passkeys WHERE id = ? AND user_id = ?", (str(credential.get("id")), pending["user_id"])
        )
        .fetchone()
    )
    if row is None:
        return False
    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=webauthn.base64url_to_bytes(pending["challenge"]),
            expected_rp_id=webauthn_rp_id(),
            expected_origin=webauthn_origins(),
            credential_public_key=webauthn.base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=row["sign_count"],
        )
    except Exception as e:
        print("passkey login failed:", e)
        return False
    conn = get_db()
    conn.execute(
        "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?",
        (verified.new_sign_count, db.now_iso(), row["id"]),
    )
    return True


def check_totp(user, code):
    step = totp.verify(user["totp_secret"], code, last_step=user["totp_last_step"])
    if step is None:
        return False
    get_db().execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
    return True


def check_backup_code(user, data):
    """A backup code also works as second factor (and is used up)."""
    slot = str(data.get("slot", "")).strip().upper()
    auth_hash = data.get("auth_hash")
    if not SLOT_RE.match(slot) or not isinstance(auth_hash, str):
        return False
    conn = get_db()
    code = conn.execute(
        "SELECT * FROM recovery_codes WHERE user_id = ? AND slot = ? AND used_at IS NULL", (user["id"], slot)
    ).fetchone()
    if code is None or not verify_hash(code["auth_hash"], auth_hash):
        return False
    conn.execute(
        "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND slot = ?", (db.now_iso(), user["id"], slot)
    )
    return True


@app.route("/api/login/2fa", methods=["POST"])
def login_second_factor():
    data = json_body()
    if rate_limited(("login-2fa", client_ip()), 30, 300):
        return error("Too many attempts, please wait a few minutes", 429)
    pending = find_challenge(data.get("token"), "login")
    if pending is None:
        return error("The login expired, please log in again", 401)
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (pending["user_id"],)).fetchone()
    method = data.get("method")
    if method == "passkey":
        passed = check_passkey(pending, data.get("credential"))
    elif method == "totp":
        passed = check_totp(user, data.get("code"))
    elif method == "backup":
        passed = check_backup_code(user, data)
    else:
        return error("Unknown method")
    if not passed:
        attempts = pending["attempts"] + 1
        if attempts >= TWOFA_MAX_ATTEMPTS:
            conn.execute("DELETE FROM twofa_challenges WHERE token_hash = ?", (pending["token_hash"],))
            conn.commit()
            return error("Too many wrong attempts, please log in again", 401)
        conn.execute("UPDATE twofa_challenges SET attempts = ? WHERE token_hash = ?", (attempts, pending["token_hash"]))
        conn.commit()
        return error("The code or passkey is wrong")
    conn.execute("DELETE FROM twofa_challenges WHERE token_hash = ?", (pending["token_hash"],))
    conn.commit()
    return login_response(user["id"])


# --------------------------------------------------------------------------
# Password reset by e-mail
# --------------------------------------------------------------------------
# Without the password (or a backup code) the old private keys can't be
# unlocked, so a reset by e-mail creates new keys: the account, friends and
# chats stay, but the user can't read their old encrypted messages anymore.

RESET_MINUTES = 60

RESET_MAIL = {
    "en": (
        "Reset your SereS password",
        "Hi {name},\n\nsomeone (hopefully you) asked to reset the password of your SereS account.\n"
        "Open this link within {minutes} minutes to choose a new password:\n\n{link}\n\n"
        "Important: because your chats are end-to-end encrypted, you won't be able to read your old "
        "messages after a reset by e-mail. If you still have a backup code, use \"Forgot password?\" "
        "with the code instead – then you keep everything.\n\n"
        "If you didn't ask for this, you can ignore this e-mail. Your password stays the same.\n",
    ),
    "de": (
        "SereS-Passwort zurücksetzen",
        "Hallo {name},\n\njemand (hoffentlich du) möchte das Passwort deines SereS-Kontos zurücksetzen.\n"
        "Öffne diesen Link innerhalb von {minutes} Minuten, um ein neues Passwort zu wählen:\n\n{link}\n\n"
        "Wichtig: Da deine Chats Ende-zu-Ende-verschlüsselt sind, kannst du deine alten Nachrichten nach "
        "einem Zurücksetzen per E-Mail nicht mehr lesen. Wenn du noch einen Backup-Code hast, nutze lieber "
        "\"Passwort vergessen?\" mit dem Code – dann bleibt alles erhalten.\n\n"
        "Falls du das nicht warst, ignoriere diese E-Mail einfach. Dein Passwort bleibt unverändert.\n",
    ),
    "fr": (
        "Réinitialiser ton mot de passe SereS",
        "Bonjour {name},\n\nquelqu'un (toi, espérons-le) a demandé à réinitialiser le mot de passe de ton compte SereS.\n"
        "Ouvre ce lien dans les {minutes} minutes pour choisir un nouveau mot de passe :\n\n{link}\n\n"
        "Important : comme tes discussions sont chiffrées de bout en bout, tu ne pourras plus lire tes anciens "
        "messages après une réinitialisation par e-mail. Si tu as encore un code de secours, utilise plutôt "
        "« Mot de passe oublié ? » avec le code – tu gardes alors tout.\n\n"
        "Si ce n'était pas toi, ignore simplement cet e-mail. Ton mot de passe reste inchangé.\n",
    ),
}


def public_base_url():
    return (os.getenv("PUBLIC_URL") or flask.request.host_url).rstrip("/")


@app.route("/api/password_reset/request", methods=["POST"])
def request_password_reset():
    """Sends a reset link. The answer is the same whether the account exists or not."""
    data = json_body()
    nameomail = str_field(data, "nameomail", 254).strip()
    lang = data.get("lang") if data.get("lang") in RESET_MAIL else "en"
    if not mailer.configured():
        return error("Password reset by e-mail is not set up on this server", 503)
    if rate_limited(("reset-ip", client_ip()), 10, 3600) or rate_limited(
        ("reset-account", nameomail.lower()), 3, 3600
    ):
        return error("Too many attempts, please try again later", 429)
    user = find_user_by_login(nameomail)
    if user is not None and user["email"] and EMAIL_RE.match(user["email"]):
        token = secrets.token_urlsafe(32)
        conn = get_db()
        # Only the newest link works.
        conn.execute("DELETE FROM password_resets WHERE user_id = ?", (user["id"],))
        conn.execute(
            "INSERT INTO password_resets (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (hash_token(token), user["id"], db.now_iso(), iso_in(RESET_MINUTES * 60)),
        )
        conn.commit()
        subject, body = RESET_MAIL[lang]
        link = f"{public_base_url()}/login.html?reset={token}"
        mailer.send_async(
            user["email"], subject, body.format(name=display_name(user), minutes=RESET_MINUTES, link=link)
        )
    return ok(message="If the account exists, an e-mail with a link is on its way.")


def reset_user(token):
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    return (
        get_db()
        .execute(
            """SELECT u.* FROM password_resets r JOIN users u ON u.id = r.user_id
               WHERE r.token_hash = ? AND r.used_at IS NULL AND r.expires_at > ?""",
            (hash_token(token), db.now_iso()),
        )
        .fetchone()
    )


@app.route("/api/password_reset/check", methods=["POST"])
def check_password_reset():
    if rate_limited(("reset-check", client_ip()), 30, 600):
        return error("Too many attempts, please try again later", 429)
    user = reset_user(json_body().get("token"))
    if user is None:
        return error("This link is invalid or expired", 404)
    if twofa_methods(user):
        return two_factor_blocks_reset()
    return ok(username=user["username"], display_name=display_name(user))


def two_factor_blocks_reset():
    # Otherwise access to the mailbox alone would be enough to take over the account.
    return {
        "message": "Two-factor authentication is on: please use a backup code to reset your password",
        "success": False,
        "two_factor": True,
    }, 403


@app.route("/api/password_reset/confirm", methods=["POST"])
def confirm_password_reset():
    """New password and new keys. Old messages stay for the others but are hidden for this user."""
    data = json_body()
    if rate_limited(("reset-check", client_ip()), 30, 600):
        return error("Too many attempts, please try again later", 429)
    user = reset_user(data.get("token"))
    if user is None:
        return error("This link is invalid or expired", 404)
    if twofa_methods(user):
        return two_factor_blocks_reset()
    auth_hash = b64_field(data, "auth_hash", 128)
    kdf_salt, kdf_iterations = validate_kdf(data)
    keys = validate_key_bundle(data)
    conn = get_db()
    with db.write_transaction(conn):
        used = conn.execute(
            "UPDATE password_resets SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (db.now_iso(), hash_token(data["token"])),
        )
        if used.rowcount == 0:
            flask.abort(flask.make_response(error("This link is invalid or expired", 404)))
        if user["pub_ecdh"] and user["pub_sign"]:
            # Others still verify the old messages with the old keys.
            conn.execute(
                "INSERT INTO user_key_history (user_id, pub_ecdh, pub_sign, replaced_at) VALUES (?, ?, ?, ?)",
                (user["id"], user["pub_ecdh"], user["pub_sign"], db.now_iso()),
            )
        conn.execute(
            """UPDATE users SET passwd = ?, auth_version = 1, kdf_salt = ?, kdf_iterations = ?,
                      pub_ecdh = ?, pub_sign = ?, enc_private = ? WHERE id = ?""",
            (ph.hash(auth_hash), kdf_salt, kdf_iterations, keys["pub_ecdh"], keys["pub_sign"],
             keys["enc_private"], user["id"]),
        )
        # Backup codes wrapped the old keys, they are useless now.
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
        conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user["id"],))
        # Shared keys were wrapped for the old keys as well.
        conn.execute("DELETE FROM message_key_shares WHERE recipient_id = ?", (user["id"],))
        for chat in conn.execute(
            "SELECT chat_id, joined_seq, cleared_seq, reset_seq, reset_cleared_seq FROM chat_members WHERE user_id = ?",
            (user["id"],),
        ).fetchall():
            # The old messages can't be decrypted with the new keys: hide them for
            # this user until another member shares them again.
            until = max_seq(conn, chat["chat_id"])
            before = chat["reset_cleared_seq"] if chat["reset_seq"] else chat["cleared_seq"]
            waiting = until if db.has_encrypted_between(conn, chat["chat_id"], max(chat["joined_seq"], before), until) else 0
            conn.execute(
                """UPDATE chat_members SET cleared_seq = ?, reset_seq = ?, reset_cleared_seq = ?
                   WHERE chat_id = ? AND user_id = ?""",
                (until, waiting, before if waiting else 0, chat["chat_id"], user["id"]),
            )
            add_system_message(conn, chat["chat_id"], "keys_reset", actor=display_name(user))
    return login_response(user["id"])


@app.route("/api/users/keys")
@login_required
def user_keys():
    ids = [i for i in flask.request.args.get("ids", "").split(",") if i][:100]
    if not ids:
        return ok(users=[])
    placeholders = ",".join("?" * len(ids))
    rows = get_db().execute(
        f"SELECT id, username, display_name, pub_ecdh, pub_sign FROM users WHERE id IN ({placeholders})", ids
    )
    history = previous_keys(ids)
    return ok(
        users=[
            {**dict(row), "display_name": display_name(row), "previous_keys": history.get(row["id"], [])}
            for row in rows
        ]
    )


def previous_keys(user_ids):
    """Keys replaced by a reset, oldest first: {user_id: [{pub_ecdh, pub_sign, until}]}."""
    if not user_ids:
        return {}
    placeholders = ",".join("?" * len(user_ids))
    rows = get_db().execute(
        f"""SELECT user_id, pub_ecdh, pub_sign, replaced_at FROM user_key_history
            WHERE user_id IN ({placeholders}) ORDER BY replaced_at""",
        list(user_ids),
    )
    result = {}
    for row in rows:
        result.setdefault(row["user_id"], []).append(
            {"pub_ecdh": row["pub_ecdh"], "pub_sign": row["pub_sign"], "until": row["replaced_at"]}
        )
    return result


# --------------------------------------------------------------------------
# Avatars
# --------------------------------------------------------------------------


def avatar_path(user_id):
    return os.path.join(USER_DATA, user_id, "avatar.png")


def send_avatar(user_id):
    path = avatar_path(user_id)
    if not os.path.exists(path):
        return error("No avatar uploaded", 404)
    response = flask.send_file(path, mimetype="image/png", max_age=300)
    return response


@app.route("/api/get_avatar")
@login_required
def get_avatar():
    return send_avatar(current_user()["id"])


def can_see_user(viewer_id, other_id):
    if viewer_id == other_id or are_friends(viewer_id, other_id):
        return True
    return (
        get_db()
        .execute(
            """SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id = b.chat_id
               WHERE a.user_id = ? AND b.user_id = ? LIMIT 1""",
            (viewer_id, other_id),
        )
        .fetchone()
        is not None
    )


@app.route("/api/users/<username>/avatar")
@login_required
def get_user_avatar(username):
    other = find_user_by_name(username)
    if other is None or not can_see_user(current_user()["id"], other["id"]):
        return error("No avatar uploaded", 404)
    return send_avatar(other["id"])


@app.route("/api/upload_avatar", methods=["POST"])
@login_required
def upload_avatar():
    user_id = current_user()["id"]
    file = flask.request.files.get("avatar_img")
    if file is None or not file.filename:
        return error("No selected file")
    raw = file.read(MAX_AVATAR_BYTES + 1)
    if len(raw) > MAX_AVATAR_BYTES:
        return error("File size exceeds 2MB limit")
    try:
        image = Image.open(io.BytesIO(raw))
        if image.width * image.height > 40_000_000:
            return error("Image is too large")
        image = image.convert("RGBA")
        image.thumbnail((512, 512))
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        return error("Wrong filetype (png, jpg, gif or webp)")
    os.makedirs(os.path.join(USER_DATA, user_id), exist_ok=True)
    # Re-encoding strips metadata and anything that is not plain pixel data.
    image.save(avatar_path(user_id), "PNG")
    return {"message": "Image uploaded successfully", "success": True}, 200


# --------------------------------------------------------------------------
# Friends & blocking
# --------------------------------------------------------------------------


def pair(a, b):
    return tuple(sorted((a, b)))


def are_friends(a, b):
    return (
        get_db()
        .execute("SELECT 1 FROM friendships WHERE user_a = ? AND user_b = ?", pair(a, b))
        .fetchone()
        is not None
    )


def is_blocked_between(a, b):
    return (
        get_db()
        .execute(
            "SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)",
            (a, b, b, a),
        )
        .fetchone()
        is not None
    )


def target_user(data):
    other = find_user_by_name(data.get("username") or data.get("friend_username"))
    if other is None:
        flask.abort(flask.make_response(error("User not found", 404)))
    return other


def users_by_query(sql, params):
    return [public_user(row) for row in get_db().execute(sql, params)]


@app.route("/api/friends")
@login_required
def list_friends():
    me_id = current_user()["id"]
    return ok(
        friends=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM friendships f JOIN users u
               ON u.id = CASE WHEN f.user_a = ? THEN f.user_b ELSE f.user_a END
               WHERE f.user_a = ? OR f.user_b = ? ORDER BY COALESCE(u.display_name, u.username) COLLATE NOCASE""",
            (me_id, me_id, me_id),
        ),
        incoming=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM friend_requests r JOIN users u ON u.id = r.from_id
               WHERE r.to_id = ? ORDER BY r.created_at""",
            (me_id,),
        ),
        outgoing=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM friend_requests r JOIN users u ON u.id = r.to_id
               WHERE r.from_id = ? ORDER BY r.created_at""",
            (me_id,),
        ),
        blocked=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM blocks b JOIN users u ON u.id = b.blocked_id
               WHERE b.blocker_id = ? ORDER BY u.username COLLATE NOCASE""",
            (me_id,),
        ),
    )


def make_friends(conn, a, b):
    conn.execute(
        "INSERT OR IGNORE INTO friendships (user_a, user_b, created_at) VALUES (?, ?, ?)",
        (*pair(a, b), db.now_iso()),
    )
    conn.execute(
        "DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
        (a, b, b, a),
    )


@app.route("/api/friends/request", methods=["POST"])
@app.route("/api/add_friend", methods=["POST"])
@login_required
def request_friend():
    return send_friend_request(current_user()["id"], target_user(json_body()))


def send_friend_request(me_id, other):
    if rate_limited(("friend-request", me_id), 30, 600):
        return error("Too many friend requests, please wait", 429)
    if other["id"] == me_id:
        return error("Cannot add yourself as a friend")
    if are_friends(me_id, other["id"]):
        return error("Already Friends")
    if is_blocked_between(me_id, other["id"]):
        # Do not reveal who blocked whom.
        return error("Friend request could not be sent")
    conn = get_db()
    if conn.execute(
        "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", (other["id"], me_id)
    ).fetchone():
        make_friends(conn, me_id, other["id"])
        conn.commit()
        return ok(message="Friend added successfully!", status="friends")
    if conn.execute(
        "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", (me_id, other["id"])
    ).fetchone():
        return error("Already pending request")
    conn.execute(
        "INSERT INTO friend_requests (from_id, to_id, created_at) VALUES (?, ?, ?)",
        (me_id, other["id"], db.now_iso()),
    )
    conn.commit()
    return ok(message="Request sent", status="pending")


# ------------------------------------------------------------ invite links


def invite_token(user_id, renew=False):
    conn = get_db()
    row = conn.execute("SELECT token FROM friend_invites WHERE user_id = ?", (user_id,)).fetchone()
    if row and not renew:
        return row["token"]
    token = secrets.token_urlsafe(16)
    conn.execute(
        "INSERT INTO friend_invites (token, user_id, created_at) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET token = excluded.token, created_at = excluded.created_at",
        (token, user_id, db.now_iso()),
    )
    conn.commit()
    return token


def invite_owner(token):
    if rate_limited(("invite", client_ip()), 60, 60):
        flask.abort(flask.make_response(error("Too many requests, please wait", 429)))
    row = get_db().execute(
        """SELECT u.* FROM friend_invites i JOIN users u ON u.id = i.user_id
           WHERE i.token = ?""",
        (token[:64],),
    ).fetchone()
    if row is None:
        flask.abort(flask.make_response(error("This invite link is invalid or expired", 404)))
    return row


@app.route("/api/invite")
@login_required
def my_invite():
    return ok(token=invite_token(current_user()["id"]))


@app.route("/api/invite/renew", methods=["POST"])
@login_required
def renew_invite():
    # The old link stops working.
    return ok(token=invite_token(current_user()["id"], renew=True))


@app.route("/api/invite/<token>")
@login_required
def show_invite(token):
    owner = invite_owner(token)
    me_id = current_user()["id"]
    status = "self" if owner["id"] == me_id else "friends" if are_friends(me_id, owner["id"]) else "none"
    return ok(user=public_user(owner), status=status)


@app.route("/api/invite/<token>/accept", methods=["POST"])
@login_required
def accept_invite(token):
    return send_friend_request(current_user()["id"], invite_owner(token))


@app.route("/api/friends/accept", methods=["POST"])
@login_required
def accept_friend():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    if not conn.execute(
        "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", (other["id"], me_id)
    ).fetchone():
        return error("Request doesnt exist")
    make_friends(conn, me_id, other["id"])
    conn.commit()
    return ok(message="Friend added successfully!")


@app.route("/api/friends/decline", methods=["POST"])
@app.route("/api/discard_request", methods=["POST"])
@login_required
def decline_friend():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    cur = conn.execute(
        "DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", (other["id"], me_id)
    )
    conn.commit()
    if cur.rowcount == 0:
        return error("Request doesnt exist")
    return ok(message="successfully deleted the request")


@app.route("/api/friends/cancel", methods=["POST"])
@login_required
def cancel_friend_request():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    conn.execute("DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", (me_id, other["id"]))
    conn.commit()
    return ok(message="Request cancelled")


@app.route("/api/friends/remove", methods=["POST"])
@login_required
def remove_friend():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    conn.execute("DELETE FROM friendships WHERE user_a = ? AND user_b = ?", pair(me_id, other["id"]))
    conn.commit()
    return ok(message="Friend removed")


@app.route("/api/block", methods=["POST"])
@app.route("/api/block_user", methods=["POST"])
@login_required
def block_user():
    me_id = current_user()["id"]
    other = target_user(json_body())
    if other["id"] == me_id:
        return error("Cannot block yourself")
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at, was_friend) VALUES (?, ?, ?, ?)",
        (me_id, other["id"], db.now_iso(), int(are_friends(me_id, other["id"]))),
    )
    conn.execute("DELETE FROM friendships WHERE user_a = ? AND user_b = ?", pair(me_id, other["id"]))
    conn.execute(
        "DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
        (me_id, other["id"], other["id"], me_id),
    )
    conn.commit()
    return ok(message="User blocked")


@app.route("/api/unblock", methods=["POST"])
@login_required
def unblock_user():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    row = conn.execute(
        "SELECT was_friend FROM blocks WHERE blocker_id = ? AND blocked_id = ?", (me_id, other["id"])
    ).fetchone()
    conn.execute("DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?", (me_id, other["id"]))
    restored = bool(row and row["was_friend"]) and not is_blocked_between(me_id, other["id"])
    if restored:
        make_friends(conn, me_id, other["id"])
    conn.commit()
    return ok(message="User unblocked", friends=restored)


def is_muted(me_id, other_id):
    return (
        get_db()
        .execute("SELECT 1 FROM muted_users WHERE user_id = ? AND muted_id = ?", (me_id, other_id))
        .fetchone()
        is not None
    )


@app.route("/api/users/mute", methods=["POST"])
@login_required
def mute_user():
    me_id = current_user()["id"]
    data = json_body()
    other = target_user(data)
    conn = get_db()
    if data.get("muted") is True:
        conn.execute(
            "INSERT OR IGNORE INTO muted_users (user_id, muted_id, created_at) VALUES (?, ?, ?)",
            (me_id, other["id"], db.now_iso()),
        )
    else:
        conn.execute("DELETE FROM muted_users WHERE user_id = ? AND muted_id = ?", (me_id, other["id"]))
    conn.commit()
    return ok(muted=data.get("muted") is True)


@app.route("/api/users/<username>/profile")
@login_required
def user_profile(username):
    me_id = current_user()["id"]
    other = find_user_by_name(username)
    if other is None:
        return error("User not found", 404)
    conn = get_db()
    request_row = conn.execute(
        "SELECT from_id FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
        (me_id, other["id"], other["id"], me_id),
    ).fetchone()
    return ok(
        user={**public_user(other), "pub_ecdh": other["pub_ecdh"], "pub_sign": other["pub_sign"]},
        is_me=other["id"] == me_id,
        friend=are_friends(me_id, other["id"]),
        blocked=conn.execute(
            "SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?", (me_id, other["id"])
        ).fetchone()
        is not None,
        muted=is_muted(me_id, other["id"]),
        request=None if request_row is None else "outgoing" if request_row["from_id"] == me_id else "incoming",
        presence=presence(current_user(), other) if can_see_user(me_id, other["id"]) and other["id"] != me_id else None,
    )


# --------------------------------------------------------------------------
# Chats
# --------------------------------------------------------------------------


def membership(chat_id, user_id):
    return (
        get_db()
        .execute(
            """SELECT c.*, m.role, m.joined_seq, m.cleared_seq, m.last_read_seq, m.hidden,
                      m.pinned, m.archived
               FROM chats c JOIN chat_members m ON m.chat_id = c.id
               WHERE c.id = ? AND m.user_id = ?""",
            (chat_id, user_id),
        )
        .fetchone()
    )


def require_membership(chat_id):
    chat = membership(chat_id, current_user()["id"])
    if chat is None:
        flask.abort(flask.make_response(error("Chat not found", 404)))
    return chat


def chat_members(chat_id):
    return get_db().execute(
        """SELECT u.id, u.username, u.display_name, u.pub_ecdh, u.pub_sign, m.role,
                  u.last_seen, u.show_last_seen, m.joined_seq, m.reset_seq, m.reset_cleared_seq
           FROM chat_members m JOIN users u ON u.id = m.user_id
           WHERE m.chat_id = ? ORDER BY m.joined_at, u.username COLLATE NOCASE""",
        (chat_id,),
    ).fetchall()


def history_reset(member):
    """Messages a member can't read since a reset by e-mail, or None."""
    if not member["reset_seq"]:
        return None
    return {
        "from_seq": max(member["joined_seq"], member["reset_cleared_seq"]),
        "until_seq": member["reset_seq"],
    }


def with_shared_keys(messages, user_id):
    """Adds the message keys others shared with this user after a reset."""
    ids = [message["id"] for message in messages]
    if not ids:
        return messages
    placeholders = ",".join("?" * len(ids))
    shares = {
        row["message_id"]: {"iv": row["iv"], "k": row["k"], "from_pub": row["sharer_pub_ecdh"]}
        for row in get_db().execute(
            f"""SELECT message_id, iv, k, sharer_pub_ecdh FROM message_key_shares
                WHERE recipient_id = ? AND message_id IN ({placeholders})""",
            [user_id, *ids],
        )
    }
    for message in messages:
        if message["id"] in shares:
            message["share"] = shares[message["id"]]
    return messages


def max_seq(conn, chat_id):
    return conn.execute(
        "SELECT COALESCE(MAX(seq), 0) AS s FROM messages WHERE chat_id = ?", (chat_id,)
    ).fetchone()["s"]


def serialize_message(row):
    payload = None
    if not row["deleted"] and row["payload"]:
        try:
            payload = json.loads(row["payload"])
        except ValueError:
            payload = None
    return {
        "seq": row["seq"],
        "rev": row["rev"],
        "id": row["id"],
        "sender_id": row["sender_id"],
        "sender": row["sender"],
        "sender_display": row["sender_display"] or row["sender"],
        "kind": row["kind"],
        "payload": payload,
        "created_at": row["created_at"],
        "edited_at": row["edited_at"],
        "deleted": bool(row["deleted"]),
        "silent": bool(row["silent"]),
        "expires_at": row["expires_at"],
    }


MESSAGE_SELECT = """SELECT m.*, u.username AS sender, u.display_name AS sender_display FROM messages m
                    LEFT JOIN users u ON u.id = m.sender_id"""


def add_system_message(conn, chat_id, event, **details):
    rev = db.next_rev(conn)
    conn.execute(
        "INSERT INTO messages (id, chat_id, sender_id, kind, payload, created_at, rev) VALUES (?, ?, NULL, 'system', ?, ?, ?)",
        (str(uuid.uuid4()), chat_id, json.dumps({"event": event, **details}), db.now_iso(), rev),
    )
    conn.execute("UPDATE chats SET last_activity = ? WHERE id = ?", (db.now_iso(), chat_id))


def add_member(conn, chat_id, user_id, role="member"):
    conn.execute(
        """INSERT INTO chat_members (chat_id, user_id, role, joined_at, joined_seq, cleared_seq, last_read_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (chat_id, user_id, role, db.now_iso(), max_seq(conn, chat_id), 0, max_seq(conn, chat_id)),
    )


def chat_summary(chat, me_id):
    conn = get_db()
    floor = max(chat["joined_seq"], chat["cleared_seq"])
    last = conn.execute(
        MESSAGE_SELECT
        + " WHERE m.chat_id = ? AND m.seq > ? AND m.deleted = 0 AND m.silent = 0 ORDER BY m.seq DESC LIMIT 1",
        (chat["id"], floor),
    ).fetchone()
    unread = conn.execute(
        """SELECT COUNT(*) AS c FROM messages WHERE chat_id = ? AND seq > ? AND deleted = 0
           AND silent = 0 AND kind != 'system' AND (sender_id IS NULL OR sender_id != ?)""",
        (chat["id"], max(floor, chat["last_read_seq"]), me_id),
    ).fetchone()["c"]
    members = chat_members(chat["id"])
    summary = {
        "id": chat["id"],
        "chat": chat["id"],
        "type": chat["type"],
        "name": chat["name"],
        "role": chat["role"],
        "member_count": len(members),
        "last_message": serialize_message(last) if last else None,
        "unread": unread,
        "last_activity": chat["last_activity"],
        "pinned": bool(chat["pinned"]),
        "archived": bool(chat["archived"]),
        "disappear_seconds": chat["disappear_seconds"],
    }
    if chat["type"] == "dm":
        others = [m for m in members if m["id"] != me_id]
        other = others[0] if others else None
        summary["other_user"] = other["username"] if other else "Unknown User"
        summary["other_user_id"] = other["id"] if other else None
        summary["name"] = display_name(other) if other else summary["other_user"]
        summary["blocked"] = bool(other) and is_blocked_between(me_id, other["id"])
        summary["muted"] = bool(other) and is_muted(me_id, other["id"])
        summary["presence"] = presence(current_user(), other)
    summary["typing"] = typing_users(chat["id"], me_id)
    return summary


@app.route("/api/chats")
@app.route("/api/load_chats")
@login_required
def list_chats():
    me_id = current_user()["id"]
    rows = get_db().execute(
        """SELECT c.*, m.role, m.joined_seq, m.cleared_seq, m.last_read_seq, m.hidden,
                  m.pinned, m.archived
           FROM chats c JOIN chat_members m ON m.chat_id = c.id
           WHERE m.user_id = ? AND m.hidden = 0 ORDER BY c.last_activity DESC""",
        (me_id,),
    ).fetchall()
    conn = get_db()
    purge_expired(conn)
    for row in rows:
        advance_receipt(conn, row["id"], me_id, "delivered", max_seq(conn, row["id"]))
    conn.commit()
    return ok(chats=[chat_summary(row, me_id) for row in rows])


def open_dm(me_id, other):
    if other["id"] == me_id:
        return error("Cannot create chat with yourself")
    if is_blocked_between(me_id, other["id"]):
        return error("Cannot create chat with this user")
    a, b = pair(me_id, other["id"])
    conn = get_db()
    existing = conn.execute("SELECT id FROM chats WHERE dm_key = ?", (f"{a}:{b}",)).fetchone()
    if existing:
        mine = membership(existing["id"], me_id)
        if mine is None:
            add_member(conn, existing["id"], me_id)
        else:
            conn.execute(
                "UPDATE chat_members SET hidden = 0 WHERE chat_id = ? AND user_id = ?",
                (existing["id"], me_id),
            )
        conn.commit()
        return ok(chat_id=existing["id"], message="Chat already exists", existing=True)
    if not are_friends(me_id, other["id"]):
        return error("Cannot create chat with a user who is not your friend")
    chat_id = str(uuid.uuid4())
    now = db.now_iso()
    conn.execute(
        "INSERT INTO chats (id, type, name, owner_id, dm_key, created_at, last_activity) VALUES (?, 'dm', NULL, NULL, ?, ?, ?)",
        (chat_id, f"{a}:{b}", now, now),
    )
    add_member(conn, chat_id, me_id)
    add_member(conn, chat_id, other["id"])
    conn.commit()
    return ok(chat_id=chat_id, message="Chat created successfully!")


@app.route("/api/profile/display_name", methods=["POST"])
@login_required
def set_display_name():
    value = json_body().get("display_name")
    if value is not None and not isinstance(value, str):
        return error("Invalid display name")
    value = " ".join((value or "").split())  # no line breaks or repeated spaces
    if len(value) > 32:
        return error("Display name can be at most 32 characters")
    conn = get_db()
    conn.execute("UPDATE users SET display_name = ? WHERE id = ?", (value or None, current_user()["id"]))
    conn.commit()
    return ok(display_name=value or current_user()["username"])


def validate_group_name(value):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 64:
        flask.abort(flask.make_response(error("Group name must be 1-64 characters")))
    return value.strip()


@app.route("/api/chats", methods=["POST"])
@login_required
def create_chat():
    data = json_body()
    me = current_user()
    if data.get("type", "dm") == "dm":
        return open_dm(me["id"], target_user(data))

    name = validate_group_name(data.get("name"))
    usernames = data.get("usernames")
    if not isinstance(usernames, list) or not usernames:
        return error("Pick at least one friend for the group")
    members = {}
    for username in usernames:
        other = find_user_by_name(username)
        if other is None or not are_friends(me["id"], other["id"]):
            return error(f"{username} is not your friend")
        members[other["id"]] = other
    members.pop(me["id"], None)
    if not members or len(members) + 1 > MAX_GROUP_MEMBERS:
        return error(f"A group needs 2-{MAX_GROUP_MEMBERS} members")

    conn = get_db()
    chat_id = str(uuid.uuid4())
    now = db.now_iso()
    conn.execute(
        "INSERT INTO chats (id, type, name, owner_id, dm_key, created_at, last_activity) VALUES (?, 'group', ?, ?, NULL, ?, ?)",
        (chat_id, name, me["id"], now, now),
    )
    add_member(conn, chat_id, me["id"], "owner")
    for user_id in members:
        add_member(conn, chat_id, user_id)
    add_system_message(conn, chat_id, "created", actor=display_name(me), name=name)
    conn.commit()
    return ok(chat_id=chat_id, message="Group created successfully!")


@app.route("/api/new_chat", methods=["POST"])
@login_required
def new_chat_legacy():
    return open_dm(current_user()["id"], target_user(json_body()))


@app.route("/api/chats/<chat_id>")
@login_required
def chat_details(chat_id):
    chat = require_membership(chat_id)
    me_id = current_user()["id"]
    summary = chat_summary(chat, me_id)
    members = chat_members(chat_id)
    history = previous_keys([row["id"] for row in members])
    summary["members"] = [
        {
            "id": row["id"],
            "username": row["username"],
            "display_name": display_name(row),
            "pub_ecdh": row["pub_ecdh"],
            "pub_sign": row["pub_sign"],
            "previous_keys": history.get(row["id"], []),
            "role": row["role"],
            "history_reset": history_reset(row),
        }
        for row in members
    ]
    summary["owner_id"] = chat["owner_id"]
    summary["pins"] = chat_pins(chat)
    return ok(chat=summary)


@app.route("/api/chats/<chat_id>/messages")
@login_required
def get_chat_messages(chat_id):
    chat = require_membership(chat_id)
    floor = max(chat["joined_seq"], chat["cleared_seq"])
    args = flask.request.args
    limit = min(max(args.get("limit", 50, type=int), 1), 200)
    conn = get_db()
    purge_expired(conn)
    if args.get("since_rev") is not None:
        rows = conn.execute(
            MESSAGE_SELECT + " WHERE m.chat_id = ? AND m.seq > ? AND m.rev > ? ORDER BY m.rev ASC LIMIT ?",
            (chat_id, floor, args.get("since_rev", 0, type=int), limit),
        ).fetchall()
    else:
        before = args.get("before_seq", type=int)
        rows = conn.execute(
            MESSAGE_SELECT
            + " WHERE m.chat_id = ? AND m.seq > ? AND m.seq < ? ORDER BY m.seq DESC LIMIT ?",
            (chat_id, floor, before if before else 2**62, limit),
        ).fetchall()[::-1]
    if rows:
        advance_receipt(conn, chat_id, current_user()["id"], "delivered", max(row["seq"] for row in rows))
        conn.commit()
    return ok(
        messages=with_shared_keys([serialize_message(row) for row in rows], current_user()["id"]),
        has_more=len(rows) == limit,
        typing=typing_users(chat_id, current_user()["id"]),
        receipts=member_receipts(chat_id, current_user()["id"]),
    )


@app.route("/api/get_messages")
@login_required
def get_messages_legacy():
    return get_chat_messages(flask.request.args.get("chat_id", ""))


def validate_envelope(payload, member_ids):
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return "Unsupported message format"
    for field, max_len in (("iv", 64), ("sig", 256), ("ct", MAX_CIPHERTEXT_LEN)):
        value = payload.get(field)
        if not isinstance(value, str) or not value or len(value) > max_len or not B64_RE.match(value):
            return f"Invalid '{field}'"
    keys = payload.get("keys")
    if not isinstance(keys, dict) or set(keys) != set(member_ids):
        return "Message must be encrypted for exactly the current chat members"
    for wrapped in keys.values():
        if not isinstance(wrapped, dict):
            return "Invalid key"
        for field in ("iv", "k"):
            value = wrapped.get(field)
            if not isinstance(value, str) or len(value) > 128 or not B64_RE.match(value):
                return "Invalid key"
    if set(payload) - {"v", "iv", "ct", "sig", "keys"}:
        return "Unknown fields in message"
    return None


@app.route("/api/chats/<chat_id>/messages", methods=["POST"])
@login_required
def post_message(chat_id):
    me_id = current_user()["id"]
    chat = require_membership(chat_id)
    data = json_body()
    message_id = str_field(data, "id", 64)
    try:
        uuid.UUID(message_id)
    except ValueError:
        return error("Invalid message id")
    if rate_limited(("send", me_id), 30, 10):
        return error("You are sending messages too fast", 429)

    members = chat_members(chat_id)
    if chat["type"] == "dm":
        others = [m["id"] for m in members if m["id"] != me_id]
        if others and is_blocked_between(me_id, others[0]):
            return error("You can't send messages to this chat", 403)
    problem = validate_envelope(data.get("payload"), [m["id"] for m in members])
    if problem:
        return error(problem, 409 if "members" in problem else 400)
    # Silent messages (reactions) don't bump the chat or count as unread.
    silent = data.get("silent") is True
    file_ids = data.get("files") or []
    if (
        not isinstance(file_ids, list)
        or len(file_ids) > MAX_FILES_PER_MESSAGE
        or not all(isinstance(f, str) and len(f) <= 64 for f in file_ids)
    ):
        return error("Invalid files")
    expires_at = iso_in(chat["disappear_seconds"]) if chat["disappear_seconds"] else None

    conn = get_db()
    try:
        with db.write_transaction(conn):
            for file_id in file_ids:
                attached = conn.execute(
                    """UPDATE files SET message_id = ? WHERE id = ? AND chat_id = ? AND uploader_id = ?
                       AND message_id IS NULL""",
                    (message_id, file_id, chat_id, me_id),
                )
                if attached.rowcount == 0:
                    raise LookupError(file_id)
            rev = db.next_rev(conn)
            cur = conn.execute(
                """INSERT INTO messages (id, chat_id, sender_id, kind, payload, created_at, rev, silent, expires_at)
                   VALUES (?, ?, ?, 'e2e', ?, ?, ?, ?, ?)""",
                (message_id, chat_id, me_id, json.dumps(data["payload"]), db.now_iso(), rev, int(silent), expires_at),
            )
            if not silent:
                conn.execute("UPDATE chats SET last_activity = ? WHERE id = ?", (db.now_iso(), chat_id))
                conn.execute("UPDATE chat_members SET hidden = 0 WHERE chat_id = ?", (chat_id,))
            conn.execute(
                "UPDATE chat_members SET last_read_seq = ?, delivered_seq = ? WHERE chat_id = ? AND user_id = ?",
                (cur.lastrowid, cur.lastrowid, chat_id, me_id),
            )
    except sqlite3.IntegrityError:
        return error("Duplicate message id", 409)
    except LookupError:
        return error("Attachment not found, please upload it again", 400)
    with typing_lock:
        typing_state.pop((chat_id, me_id), None)
    return ok(message="Message sent successfully!", seq=cur.lastrowid, rev=rev)


@app.route("/api/send_message", methods=["POST"])
@login_required
def send_message_legacy():
    return error("This client is outdated. Please reload the page to use encrypted messaging.", 410)


@app.route("/api/chats/<chat_id>/messages/<message_id>/delete", methods=["POST"])
@login_required
def delete_message(chat_id, message_id):
    require_membership(chat_id)
    conn = get_db()
    with db.write_transaction(conn):
        cur = conn.execute(
            "UPDATE messages SET deleted = 1, payload = NULL, rev = ? WHERE id = ? AND chat_id = ? AND sender_id = ? AND deleted = 0",
            (db.next_rev(conn), message_id, chat_id, current_user()["id"]),
        )
        if cur.rowcount:
            forget_message_data(conn, chat_id, [message_id])
    if cur.rowcount == 0:
        return error("Message not found", 404)
    return ok(message="Message deleted")


@app.route("/api/chats/<chat_id>/messages/<message_id>/edit", methods=["POST"])
@login_required
def edit_message(chat_id, message_id):
    """Replaces the encrypted content of an own message (re-encrypted by the client)."""
    me_id = current_user()["id"]
    require_membership(chat_id)
    members = chat_members(chat_id)
    problem = validate_envelope(json_body().get("payload"), [m["id"] for m in members])
    if problem:
        return error(problem, 409 if "members" in problem else 400)
    conn = get_db()
    with db.write_transaction(conn):
        cur = conn.execute(
            """UPDATE messages SET payload = ?, edited_at = ?, rev = ?
               WHERE id = ? AND chat_id = ? AND sender_id = ? AND kind = 'e2e' AND deleted = 0""",
            (json.dumps(json_body()["payload"]), db.now_iso(), db.next_rev(conn), message_id, chat_id, me_id),
        )
    if cur.rowcount == 0:
        return error("Message not found", 404)
    return ok(message="Message edited")


# Who is typing right now. Kept in memory only: it is short-lived and not worth storing.
TYPING_SECONDS = 6
typing_state = {}  # (chat_id, user_id) -> time.monotonic() of the last signal
typing_lock = threading.Lock()


def typing_users(chat_id, me_id):
    now = time.monotonic()
    with typing_lock:
        ids = [
            uid for (cid, uid), at in typing_state.items()
            if cid == chat_id and uid != me_id and now - at < TYPING_SECONDS
        ]
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = get_db().execute(f"SELECT id, username, display_name FROM users WHERE id IN ({placeholders})", ids)
    return [public_user(row) for row in rows]


@app.route("/api/chats/<chat_id>/typing", methods=["POST"])
@login_required
def set_typing(chat_id):
    require_membership(chat_id)
    key = (chat_id, current_user()["id"])
    now = time.monotonic()
    with typing_lock:
        if json_body().get("typing") is False:
            typing_state.pop(key, None)
        else:
            typing_state[key] = now
        for stale in [k for k, at in typing_state.items() if now - at >= TYPING_SECONDS]:
            del typing_state[stale]
    return ok()


@app.route("/api/chats/<chat_id>/read", methods=["POST"])
@login_required
def mark_read(chat_id):
    require_membership(chat_id)
    seq = json_body().get("seq")
    if not isinstance(seq, int):
        return error("Invalid seq")
    conn = get_db()
    seq = min(seq, max_seq(conn, chat_id))
    advance_receipt(conn, chat_id, current_user()["id"], "read", seq)
    conn.commit()
    return ok()


def advance_receipt(conn, chat_id, user_id, kind, seq):
    """Moves the member's delivered/read position forward and remembers when."""
    kinds = ["delivered", "read"] if kind == "read" else ["delivered"]  # read implies delivered
    for k in kinds:
        column = "last_read_seq" if k == "read" else "delivered_seq"
        cur = conn.execute(
            f"UPDATE chat_members SET {column} = ? WHERE chat_id = ? AND user_id = ? AND {column} < ?",
            (seq, chat_id, user_id, seq),
        )
        if cur.rowcount:
            conn.execute(
                "INSERT INTO receipts (chat_id, user_id, kind, seq, at) VALUES (?, ?, ?, ?, ?)",
                (chat_id, user_id, k, seq, db.now_iso()),
            )


def member_receipts(chat_id, me_id):
    """Up to which message all other members have it delivered / have read it (for the ticks)."""
    row = get_db().execute(
        """SELECT MIN(delivered_seq) AS delivered, MIN(last_read_seq) AS read, COUNT(*) AS n
           FROM chat_members WHERE chat_id = ? AND user_id != ?""",
        (chat_id, me_id),
    ).fetchone()
    if not row["n"]:
        return None
    # Reading implies delivery (older rows may not have a delivered position yet).
    return {"delivered_seq": max(row["delivered"], row["read"]), "read_seq": row["read"]}


def receipt_time(conn, chat_id, user_id, kind, seq):
    row = conn.execute(
        "SELECT MIN(at) AS at FROM receipts WHERE chat_id = ? AND user_id = ? AND kind = ? AND seq >= ?",
        (chat_id, user_id, kind, seq),
    ).fetchone()
    return row["at"]


@app.route("/api/chats/<chat_id>/messages/<message_id>/info")
@login_required
def message_info(chat_id, message_id):
    chat = require_membership(chat_id)
    conn = get_db()
    message = conn.execute(
        "SELECT * FROM messages WHERE id = ? AND chat_id = ? AND deleted = 0 AND seq > ?",
        (message_id, chat_id, max(chat["joined_seq"], chat["cleared_seq"])),
    ).fetchone()
    if message is None:
        return error("Message not found", 404)
    members = []
    rows = conn.execute(
        """SELECT u.id, u.username, u.display_name, m.delivered_seq, m.last_read_seq, m.joined_seq
           FROM chat_members m JOIN users u ON u.id = m.user_id WHERE m.chat_id = ?""",
        (chat_id,),
    ).fetchall()
    for row in rows:
        # Skip the sender and people who joined after the message was sent.
        if row["id"] == message["sender_id"] or row["joined_seq"] >= message["seq"]:
            continue
        read = row["last_read_seq"] >= message["seq"]
        delivered = read or row["delivered_seq"] >= message["seq"]
        members.append(
            {
                **public_user(row),
                "delivered": delivered,
                "delivered_at": receipt_time(conn, chat_id, row["id"], "delivered", message["seq"]) if delivered else None,
                "read": read,
                "read_at": receipt_time(conn, chat_id, row["id"], "read", message["seq"]) if read else None,
            }
        )
    return ok(sent_at=message["created_at"], members=members)


def require_group(chat, owner_only=False):
    if chat["type"] != "group":
        flask.abort(flask.make_response(error("Only possible in groups")))
    if owner_only and chat["role"] != "owner":
        flask.abort(flask.make_response(error("Only the group owner can do that", 403)))


@app.route("/api/chats/<chat_id>/members", methods=["POST"])
@login_required
def add_group_member(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    require_group(chat)
    other = target_user(json_body())
    if not are_friends(me["id"], other["id"]):
        return error("You can only add your friends")
    if membership(chat_id, other["id"]):
        return error("Already in the group")
    conn = get_db()
    if len(chat_members(chat_id)) >= MAX_GROUP_MEMBERS:
        return error("The group is full")
    with db.write_transaction(conn):
        add_member(conn, chat_id, other["id"])
        add_system_message(conn, chat_id, "added", actor=display_name(me), target=display_name(other))
    return ok(message="Member added")


def leave_chat(conn, chat, user):
    chat_id = chat["id"]
    conn.execute("DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?", (chat_id, user["id"]))
    remaining = chat_members(chat_id)
    if not remaining:
        for row in conn.execute("SELECT id FROM files WHERE chat_id = ?", (chat_id,)).fetchall():
            remove_file_blob(row["id"])
        conn.execute("DELETE FROM files WHERE chat_id = ?", (chat_id,))
        conn.execute("DELETE FROM pinned_messages WHERE chat_id = ?", (chat_id,))
        conn.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
        conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
        return
    if chat["owner_id"] == user["id"]:
        new_owner = remaining[0]
        conn.execute("UPDATE chats SET owner_id = ? WHERE id = ?", (new_owner["id"], chat_id))
        conn.execute(
            "UPDATE chat_members SET role = 'owner' WHERE chat_id = ? AND user_id = ?",
            (chat_id, new_owner["id"]),
        )
    add_system_message(conn, chat_id, "left", actor=display_name(user))


@app.route("/api/chats/<chat_id>/members/remove", methods=["POST"])
@login_required
def remove_group_member(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    require_group(chat, owner_only=True)
    other = target_user(json_body())
    if other["id"] == me["id"]:
        return error("Use 'leave group' instead")
    if not membership(chat_id, other["id"]):
        return error("Not a member")
    conn = get_db()
    with db.write_transaction(conn):
        conn.execute("DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?", (chat_id, other["id"]))
        add_system_message(conn, chat_id, "removed", actor=display_name(me), target=display_name(other))
    return ok(message="Member removed")


@app.route("/api/chats/<chat_id>/rename", methods=["POST"])
@login_required
def rename_group(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    require_group(chat, owner_only=True)
    name = validate_group_name(json_body().get("name"))
    conn = get_db()
    with db.write_transaction(conn):
        conn.execute("UPDATE chats SET name = ? WHERE id = ?", (name, chat_id))
        add_system_message(conn, chat_id, "renamed", actor=display_name(me), name=name)
    return ok(message="Group renamed")


@app.route("/api/chats/<chat_id>/leave", methods=["POST"])
@app.route("/api/chats/<chat_id>/delete", methods=["POST"])
@login_required
def delete_chat(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    conn = get_db()
    with db.write_transaction(conn):
        if chat["type"] == "group":
            leave_chat(conn, chat, me)
        else:
            # Like WhatsApp: deleting a direct chat only clears it for yourself.
            conn.execute(
                "UPDATE chat_members SET hidden = 1, cleared_seq = ? WHERE chat_id = ? AND user_id = ?",
                (max_seq(conn, chat_id), chat_id, me["id"]),
            )
    return ok(message="Chat deleted successfully")


# --------------------------------------------------------------------------
# Attachments, pins, chat preferences, disappearing messages, privacy
# --------------------------------------------------------------------------


def file_path(file_id):
    return os.path.join(FILES, file_id)


def remove_file_blob(file_id):
    try:
        os.remove(file_path(file_id))
    except FileNotFoundError:
        # Already gone, nothing to remove.
        return


def forget_message_data(conn, chat_id, message_ids):
    """Removes attachments and pins of deleted or expired messages."""
    for message_id in message_ids:
        for row in conn.execute("SELECT id FROM files WHERE message_id = ?", (message_id,)).fetchall():
            remove_file_blob(row["id"])
        conn.execute("DELETE FROM files WHERE message_id = ?", (message_id,))
        conn.execute(
            "DELETE FROM pinned_messages WHERE chat_id = ? AND message_id = ?", (chat_id, message_id)
        )
        conn.execute("DELETE FROM message_key_shares WHERE message_id = ?", (message_id,))


_last_purge = [0.0]


def purge_expired(conn, force=False):
    """Deletes disappearing messages that expired and uploads nobody sent."""
    now = time.monotonic()
    if not force and now - _last_purge[0] < 5:
        return
    _last_purge[0] = now
    stamp = db.now_iso()
    expired = conn.execute(
        "SELECT id, chat_id FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ? AND deleted = 0",
        (stamp,),
    ).fetchall()
    stale_uploads = conn.execute(
        "SELECT id FROM files WHERE message_id IS NULL AND created_at <= ?", (iso_in(-86400),)
    ).fetchall()
    if not expired and not stale_uploads:
        return
    with db.write_transaction(conn):
        for row in expired:
            conn.execute(
                "UPDATE messages SET deleted = 1, payload = NULL, rev = ? WHERE id = ?",
                (db.next_rev(conn), row["id"]),
            )
            forget_message_data(conn, row["chat_id"], [row["id"]])
        for row in stale_uploads:
            remove_file_blob(row["id"])
            conn.execute("DELETE FROM files WHERE id = ?", (row["id"],))


@app.route("/api/chats/<chat_id>/files", methods=["POST"])
@login_required
def upload_file(chat_id):
    """Stores an encrypted attachment. The body is the raw ciphertext."""
    me_id = current_user()["id"]
    require_membership(chat_id)
    if rate_limited(("upload", me_id), 30, 60):
        return error("You are uploading too fast", 429)
    conn = get_db()
    pending = conn.execute(
        "SELECT COUNT(*) AS c FROM files WHERE uploader_id = ? AND message_id IS NULL", (me_id,)
    ).fetchone()["c"]
    if pending >= 30:
        return error("Too many unsent attachments, please try again later", 429)
    data = flask.request.get_data(cache=False)
    if not data:
        return error("Empty file")
    if len(data) > MAX_FILE_BYTES:
        return error("Files can be at most 16 MB", 413)
    file_id = uuid.uuid4().hex
    with open(file_path(file_id), "wb") as f:
        f.write(data)
    conn.execute(
        "INSERT INTO files (id, chat_id, uploader_id, message_id, size, created_at) VALUES (?, ?, ?, NULL, ?, ?)",
        (file_id, chat_id, me_id, len(data), db.now_iso()),
    )
    conn.commit()
    return ok(file_id=file_id)


@app.route("/api/chats/<chat_id>/files/<file_id>")
@login_required
def download_file(chat_id, file_id):
    chat = require_membership(chat_id)
    me_id = current_user()["id"]
    row = (
        get_db()
        .execute(
            """SELECT f.*, m.seq FROM files f LEFT JOIN messages m ON m.id = f.message_id
               WHERE f.id = ? AND f.chat_id = ?""",
            (file_id, chat_id),
        )
        .fetchone()
    )
    visible = row is not None and (
        (row["message_id"] is None and row["uploader_id"] == me_id)
        or (row["seq"] is not None and row["seq"] > max(chat["joined_seq"], chat["cleared_seq"]))
    )
    if not visible or not os.path.exists(file_path(file_id)):
        return error("File not found", 404)
    response = flask.send_file(file_path(file_id), mimetype="application/octet-stream", max_age=0)
    # Ciphertext never changes; the browser may keep it, but no shared cache.
    response.headers["Cache-Control"] = "private, max-age=604800, immutable"
    return response


@app.route("/api/chats/<chat_id>/messages/<message_id>")
@login_required
def get_single_message(chat_id, message_id):
    """One message, e.g. to show a pinned or quoted message that is not loaded yet."""
    chat = require_membership(chat_id)
    row = (
        get_db()
        .execute(
            MESSAGE_SELECT + " WHERE m.id = ? AND m.chat_id = ? AND m.seq > ?",
            (message_id, chat_id, max(chat["joined_seq"], chat["cleared_seq"])),
        )
        .fetchone()
    )
    if row is None:
        return error("Message not found", 404)
    return ok(message=with_shared_keys([serialize_message(row)], current_user()["id"])[0])


@app.route("/api/chats/<chat_id>/history/<user_id>", methods=["POST"])
@login_required
def share_history(chat_id, user_id):
    """A member who can still read the old messages gives them to someone who
    reset their password by e-mail: each message key, wrapped again for the
    new keys. Sent in parts; the last part has "done": true."""
    me = current_user()
    chat = require_membership(chat_id)
    if user_id == me["id"]:
        return error("You can't share the history with yourself")
    conn = get_db()
    target = conn.execute(
        "SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?", (chat_id, user_id)
    ).fetchone()
    if target is None:
        return error("Chat not found", 404)
    if not target["reset_seq"]:
        return error("There is nothing to share", 409)
    data = json_body()
    keys = data.get("keys") or {}
    if not isinstance(keys, dict) or len(keys) > 500:
        return error("Invalid keys")
    for message_id, wrapped in keys.items():
        if not isinstance(message_id, str) or len(message_id) > 64 or not isinstance(wrapped, dict):
            return error("Invalid keys")
        for field, max_len in (("iv", 64), ("k", 128)):
            value = wrapped.get(field)
            if not isinstance(value, str) or not value or len(value) > max_len or not B64_RE.match(value):
                return error("Invalid keys")
    # Only messages the target lost and the sharer can see.
    lowest = max(target["joined_seq"], target["reset_cleared_seq"], chat["joined_seq"], chat["cleared_seq"])
    stored = 0
    with db.write_transaction(conn):
        if keys:
            placeholders = ",".join("?" * len(keys))
            rows = conn.execute(
                f"""SELECT id FROM messages WHERE chat_id = ? AND id IN ({placeholders})
                    AND kind = 'e2e' AND deleted = 0 AND seq > ? AND seq <= ?""",
                [chat_id, *keys, lowest, target["reset_seq"]],
            ).fetchall()
            for row in rows:
                wrapped = keys[row["id"]]
                stored += conn.execute(
                    """INSERT OR IGNORE INTO message_key_shares
                       (message_id, recipient_id, sharer_id, sharer_pub_ecdh, iv, k, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (row["id"], user_id, me["id"], me["pub_ecdh"], wrapped["iv"], wrapped["k"], db.now_iso()),
                ).rowcount
        if data.get("done") is True:
            # Show the old messages again; without a shared key they say so.
            conn.execute(
                """UPDATE chat_members SET cleared_seq = MIN(cleared_seq, ?), reset_seq = 0, reset_cleared_seq = 0
                   WHERE chat_id = ? AND user_id = ? AND cleared_seq <= reset_seq""",
                (target["reset_cleared_seq"], chat_id, user_id),
            )
            conn.execute(
                "UPDATE chat_members SET reset_seq = 0, reset_cleared_seq = 0 WHERE chat_id = ? AND user_id = ?",
                (chat_id, user_id),
            )
            other = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            add_system_message(
                conn, chat_id, "history_shared", actor=display_name(me), target=display_name(other), target_id=user_id
            )
    return ok(stored=stored)


def chat_pins(chat):
    floor = max(chat["joined_seq"], chat["cleared_seq"])
    rows = get_db().execute(
        """SELECT p.message_id, p.pinned_at, m.seq, u.username, u.display_name
           FROM pinned_messages p JOIN messages m ON m.id = p.message_id
           LEFT JOIN users u ON u.id = p.pinned_by
           WHERE p.chat_id = ? AND m.deleted = 0 AND m.seq > ? ORDER BY p.pinned_at DESC""",
        (chat["id"], floor),
    ).fetchall()
    return [
        {
            "message_id": row["message_id"],
            "seq": row["seq"],
            "pinned_at": row["pinned_at"],
            "pinned_by": display_name(row) if row["username"] else None,
        }
        for row in rows
    ]


@app.route("/api/chats/<chat_id>/pins", methods=["POST"])
@login_required
def pin_message(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    data = json_body()
    message_id = str_field(data, "message_id", 64)
    pinned = data.get("pinned") is not False
    conn = get_db()
    message = conn.execute(
        "SELECT seq FROM messages WHERE id = ? AND chat_id = ? AND deleted = 0 AND silent = 0 AND kind != 'system' AND seq > ?",
        (message_id, chat_id, max(chat["joined_seq"], chat["cleared_seq"])),
    ).fetchone()
    if message is None:
        return error("Message not found", 404)
    with db.write_transaction(conn):
        if pinned:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM pinned_messages WHERE chat_id = ?", (chat_id,)
            ).fetchone()["c"]
            if count >= MAX_PINS:
                flask.abort(flask.make_response(error(f"At most {MAX_PINS} pinned messages")))
            cur = conn.execute(
                "INSERT OR IGNORE INTO pinned_messages (chat_id, message_id, pinned_by, pinned_at) VALUES (?, ?, ?, ?)",
                (chat_id, message_id, me["id"], db.now_iso()),
            )
            if cur.rowcount:
                add_system_message(conn, chat_id, "pinned", actor=display_name(me))
        else:
            conn.execute(
                "DELETE FROM pinned_messages WHERE chat_id = ? AND message_id = ?", (chat_id, message_id)
            )
    return ok(pins=chat_pins(membership(chat_id, me["id"])))


@app.route("/api/chats/<chat_id>/prefs", methods=["POST"])
@login_required
def chat_prefs(chat_id):
    """Personal settings of a chat: pinned to the top, archived."""
    require_membership(chat_id)
    data = json_body()
    conn = get_db()
    for column in ("pinned", "archived"):
        if column in data:
            if not isinstance(data[column], bool):
                return error(f"Invalid '{column}'")
            conn.execute(
                f"UPDATE chat_members SET {column} = ? WHERE chat_id = ? AND user_id = ?",
                (int(data[column]), chat_id, current_user()["id"]),
            )
    conn.commit()
    return ok()


@app.route("/api/chats/<chat_id>/disappearing", methods=["POST"])
@login_required
def set_disappearing(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    if chat["type"] == "group" and chat["role"] != "owner":
        return error("Only the group owner can do that", 403)
    seconds = json_body().get("seconds")
    if seconds not in DISAPPEAR_OPTIONS or isinstance(seconds, bool):
        return error("Invalid timer")
    if seconds == chat["disappear_seconds"]:
        return ok(disappear_seconds=seconds)
    conn = get_db()
    with db.write_transaction(conn):
        conn.execute("UPDATE chats SET disappear_seconds = ? WHERE id = ?", (seconds, chat_id))
        add_system_message(conn, chat_id, "disappearing", actor=display_name(me), seconds=seconds)
    return ok(disappear_seconds=seconds)


@app.route("/api/profile/privacy", methods=["POST"])
@login_required
def set_privacy():
    value = json_body().get("show_last_seen")
    if not isinstance(value, bool):
        return error("Invalid 'show_last_seen'")
    conn = get_db()
    conn.execute("UPDATE users SET show_last_seen = ? WHERE id = ?", (int(value), current_user()["id"]))
    conn.commit()
    return ok(show_last_seen=value)


@app.route("/api/remove_chat", methods=["POST"])
@login_required
def remove_chat_legacy():
    return delete_chat(str_field(json_body(), "chat_id", 64))


@app.route("/api/pending_friends")
@login_required
def pending_friends_legacy():
    me_id = current_user()["id"]
    names = [
        row["username"]
        for row in get_db().execute(
            "SELECT u.username FROM friend_requests r JOIN users u ON u.id = r.from_id WHERE r.to_id = ?",
            (me_id,),
        )
    ]
    return ok(pending_friends=names)


# --------------------------------------------------------------------------
# Voice calls (browser, WebRTC)
# --------------------------------------------------------------------------

ACTIVE_CALL_STATES = ("ringing", "joined")


def iso_ago(seconds):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def active_call(conn, chat_id):
    return conn.execute(
        "SELECT * FROM calls WHERE chat_id = ? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1", (chat_id,)
    ).fetchone()


def set_call_state(conn, call_id, user_id, state):
    now = db.now_iso()
    conn.execute(
        """INSERT INTO call_participants (call_id, user_id, state, updated_at, seen_at) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(call_id, user_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at,
           seen_at = excluded.seen_at""",
        (call_id, user_id, state, now, now),
    )


def finish_call_if_over(conn, call_id):
    """A call is over when nobody is in it, or one person is left and nobody rings."""
    states = [
        row["state"] for row in conn.execute("SELECT state FROM call_participants WHERE call_id = ?", (call_id,))
    ]
    joined, ringing = states.count("joined"), states.count("ringing")
    if joined == 0 or (joined == 1 and ringing == 0):
        end_call(conn, call_id)


def end_call(conn, call_id):
    call = conn.execute("SELECT * FROM calls WHERE id = ? AND ended_at IS NULL", (call_id,)).fetchone()
    if call is None:
        return
    now = db.now_iso()
    conn.execute("UPDATE calls SET ended_at = ? WHERE id = ?", (now, call_id))
    conn.execute(
        "UPDATE call_participants SET state = 'missed', updated_at = ? WHERE call_id = ? AND state = 'ringing'",
        (now, call_id),
    )
    conn.execute(
        "UPDATE call_participants SET state = 'left', updated_at = ? WHERE call_id = ? AND state = 'joined'",
        (now, call_id),
    )


def leave_other_calls(conn, user_id, keep_call_id=None):
    """Someone can only be in one call at a time."""
    rows = conn.execute(
        """SELECT p.call_id FROM call_participants p JOIN calls c ON c.id = p.call_id
           WHERE p.user_id = ? AND p.state = 'joined' AND c.ended_at IS NULL AND p.call_id != ?""",
        (user_id, keep_call_id or ""),
    ).fetchall()
    for row in rows:
        set_call_state(conn, row["call_id"], user_id, "left")
        finish_call_if_over(conn, row["call_id"])


def start_call(conn, chat_id, caller_id):
    leave_other_calls(conn, caller_id)
    call_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO calls (id, chat_id, started_by, started_at) VALUES (?, ?, ?, ?)",
        (call_id, chat_id, caller_id, db.now_iso()),
    )
    for row in conn.execute("SELECT user_id FROM chat_members WHERE chat_id = ?", (chat_id,)).fetchall():
        set_call_state(conn, call_id, row["user_id"], "joined" if row["user_id"] == caller_id else "ringing")
    return call_id


def serialize_call(conn, call, me_id):
    chat = membership(call["chat_id"], me_id)
    participants = conn.execute(
        """SELECT p.user_id, p.state, u.username, u.display_name FROM call_participants p
           JOIN users u ON u.id = p.user_id WHERE p.call_id = ? ORDER BY u.username COLLATE NOCASE""",
        (call["id"],),
    ).fetchall()
    summary = chat_summary(chat, me_id) if chat else None
    return {
        "id": call["id"],
        "chat_id": call["chat_id"],
        "chat_name": summary["name"] if summary else "",
        "chat_type": chat["type"] if chat else "dm",
        "started_by": call["started_by"],
        "started_at": call["started_at"],
        "answered_at": call["answered_at"],
        "participants": [
            {"id": row["user_id"], "username": row["username"], "display_name": display_name(row), "state": row["state"]}
            for row in participants
        ],
    }


def require_call(call_id, states=ACTIVE_CALL_STATES):
    """The active call and my part in it."""
    conn = get_db()
    call = conn.execute("SELECT * FROM calls WHERE id = ? AND ended_at IS NULL", (call_id,)).fetchone()
    mine = (
        conn.execute(
            "SELECT state FROM call_participants WHERE call_id = ? AND user_id = ?", (call_id, current_user()["id"])
        ).fetchone()
        if call
        else None
    )
    if call is None or mine is None or mine["state"] not in states:
        flask.abort(flask.make_response(error("This call has ended", 404)))
    return call


@app.route("/api/chats/<chat_id>/call", methods=["POST"])
@login_required
def call_chat(chat_id):
    """Calls everyone in the chat, or joins the call that is already running there."""
    me_id = current_user()["id"]
    chat = require_membership(chat_id)
    if chat["type"] == "dm":
        others = [m["id"] for m in chat_members(chat_id) if m["id"] != me_id]
        if not others or is_blocked_between(me_id, others[0]):
            return error("You can't call this person", 403)
    if rate_limited(("call", me_id), 20, 600):
        return error("Too many calls, please wait a moment", 429)
    conn = get_db()
    with db.write_transaction(conn):
        expire_calls(conn)
        call = active_call(conn, chat_id)
        if call is None:
            call_id = start_call(conn, chat_id, me_id)
        else:
            call_id = call["id"]
            leave_other_calls(conn, me_id, call_id)
            set_call_state(conn, call_id, me_id, "joined")
            conn.execute("UPDATE calls SET answered_at = COALESCE(answered_at, ?) WHERE id = ?", (db.now_iso(), call_id))
    call = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
    return ok(call=serialize_call(conn, call, me_id))


@app.route("/api/calls/<call_id>/answer", methods=["POST"])
@login_required
def answer_call(call_id):
    me_id = current_user()["id"]
    require_call(call_id)
    conn = get_db()
    with db.write_transaction(conn):
        leave_other_calls(conn, me_id, call_id)
        set_call_state(conn, call_id, me_id, "joined")
        conn.execute("UPDATE calls SET answered_at = COALESCE(answered_at, ?) WHERE id = ?", (db.now_iso(), call_id))
    call = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
    return ok(call=serialize_call(conn, call, me_id))


@app.route("/api/calls/<call_id>/decline", methods=["POST"])
@login_required
def decline_call(call_id):
    require_call(call_id, ("ringing",))
    conn = get_db()
    with db.write_transaction(conn):
        set_call_state(conn, call_id, current_user()["id"], "declined")
        finish_call_if_over(conn, call_id)
    return ok()


@app.route("/api/calls/<call_id>/leave", methods=["POST"])
@login_required
def leave_call(call_id):
    require_call(call_id)
    conn = get_db()
    with db.write_transaction(conn):
        set_call_state(conn, call_id, current_user()["id"], "left")
        finish_call_if_over(conn, call_id)
    return ok()


def expire_calls(conn):
    """Ringing stops after a while; people whose browser stopped asking have left."""
    stale = conn.execute(
        """SELECT p.call_id, p.user_id, p.state FROM call_participants p JOIN calls c ON c.id = p.call_id
           WHERE c.ended_at IS NULL AND ((p.state = 'ringing' AND p.updated_at < ?)
                                        OR (p.state = 'joined' AND p.seen_at < ?))""",
        (iso_ago(CALL_RING_SECONDS), iso_ago(CALL_GONE_SECONDS)),
    ).fetchall()
    for row in stale:
        set_call_state(conn, row["call_id"], row["user_id"], "missed" if row["state"] == "ringing" else "left")
    for call_id in {row["call_id"] for row in stale}:
        finish_call_if_over(conn, call_id)


CALL_RING_SECONDS = 45
CALL_GONE_SECONDS = 20


@app.route("/api/calls")
@login_required
def my_calls():
    """Polled by the browser: calls that ring for me or that I am in."""
    me_id = current_user()["id"]
    conn = get_db()
    with db.write_transaction(conn):
        expire_calls(conn)
        conn.execute(
            """UPDATE call_participants SET seen_at = ? WHERE user_id = ? AND state = 'joined'
               AND call_id IN (SELECT id FROM calls WHERE ended_at IS NULL)""",
            (db.now_iso(), me_id),
        )
    calls = conn.execute(
        """SELECT c.* FROM calls c JOIN call_participants p ON p.call_id = c.id
           WHERE p.user_id = ? AND p.state IN ('ringing', 'joined') AND c.ended_at IS NULL
           ORDER BY c.started_at""",
        (me_id,),
    ).fetchall()
    return ok(calls=[serialize_call(conn, call, me_id) for call in calls])


init_app()
start_heartbeat()

if __name__ == "__main__":
    # Never enable the Werkzeug debugger on a public interface by default.
    app.config["DEBUG"] = os.getenv("SERES_DEBUG") == "1"
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "5000")), threaded=True)
