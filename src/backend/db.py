"""Database schema and connection helpers for SereS.

Everything that used to live in loose JSON files and per-chat SQLite files
is stored in a single SQLite database. Message bodies are stored exactly as
the client sent them: an end-to-end encrypted envelope the server cannot read.
"""

import contextlib
import datetime
import secrets
import sqlite3

SCHEMA = [
    # `users` already exists on old installations with (id, email, username, passwd);
    # the extra columns are added in `_migrate_columns`.
    """CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255),
        username VARCHAR(255),
        passwd TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)",
    """CREATE TABLE IF NOT EXISTS friendships (
        user_a TEXT NOT NULL,
        user_b TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_a, user_b)
    )""",
    """CREATE TABLE IF NOT EXISTS friend_requests (
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (from_id, to_id)
    )""",
    # One invite link per user; anyone who opens it can send that user a friend request.
    """CREATE TABLE IF NOT EXISTS friend_invites (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )""",
    # Muted people: their messages don't count as unread.
    """CREATE TABLE IF NOT EXISTS muted_users (
        user_id TEXT NOT NULL,
        muted_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, muted_id)
    )""",
    """CREATE TABLE IF NOT EXISTS blocks (
        blocker_id TEXT NOT NULL,
        blocked_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (blocker_id, blocked_id)
    )""",
    """CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK (type IN ('dm', 'group')),
        name TEXT,
        owner_id TEXT,
        dm_key TEXT UNIQUE,
        created_at TEXT NOT NULL,
        last_activity TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS chat_members (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        joined_at TEXT NOT NULL,
        joined_seq INTEGER NOT NULL DEFAULT 0,
        cleared_seq INTEGER NOT NULL DEFAULT 0,
        last_read_seq INTEGER NOT NULL DEFAULT 0,
        hidden INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id)",
    """CREATE TABLE IF NOT EXISTS messages (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        chat_id TEXT NOT NULL,
        sender_id TEXT,
        kind TEXT NOT NULL CHECK (kind IN ('e2e', 'legacy', 'system')),
        payload TEXT,
        created_at TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        rev INTEGER NOT NULL DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS idx_messages_chat_seq ON messages(chat_id, seq)",
    # When a member's 'delivered' or 'read' position moved forward (for message info).
    """CREATE TABLE IF NOT EXISTS receipts (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('delivered', 'read')),
        seq INTEGER NOT NULL,
        at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_receipts ON receipts(chat_id, user_id, kind, seq)",
    "CREATE INDEX IF NOT EXISTS idx_messages_chat_rev ON messages(chat_id, rev)",
    """CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )""",
    # Pinned messages of a chat (like Discord). Only ids: the content stays encrypted.
    """CREATE TABLE IF NOT EXISTS pinned_messages (
        chat_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        pinned_by TEXT NOT NULL,
        pinned_at TEXT NOT NULL,
        PRIMARY KEY (chat_id, message_id)
    )""",
    # Encrypted attachments. The server only stores ciphertext; the key travels
    # inside the (also encrypted) message that references the file.
    """CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        uploader_id TEXT NOT NULL,
        message_id TEXT,
        size INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_files_message ON files(message_id)",
    # Backup codes (like Discord): each one can unlock the account once. The
    # private keys are stored encrypted with a key derived from each code, so a
    # code restores the account *with* its encrypted history. Only the slot (the
    # public first part of a code) is stored in plain text.
    """CREATE TABLE IF NOT EXISTS recovery_codes (
        user_id TEXT NOT NULL,
        slot TEXT NOT NULL,
        kdf_salt TEXT NOT NULL,
        auth_hash TEXT NOT NULL,
        enc_private TEXT NOT NULL,
        created_at TEXT NOT NULL,
        used_at TEXT,
        PRIMARY KEY (user_id, slot)
    )""",
    # Public keys a user had before a reset by e-mail. Messages sent before
    # `replaced_at` are checked with these keys, so others keep their history.
    """CREATE TABLE IF NOT EXISTS user_key_history (
        user_id TEXT NOT NULL,
        pub_ecdh TEXT NOT NULL,
        pub_sign TEXT NOT NULL,
        replaced_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_key_history_user ON user_key_history(user_id)",
    # Two-factor authentication: passkeys (WebAuthn) registered as second factor.
    """CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        transports TEXT,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id)",
    # Short-lived state of a 2FA step: a login waiting for its second factor,
    # or a passkey being registered. Only a hash of the token is stored.
    """CREATE TABLE IF NOT EXISTS twofa_challenges (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        challenge TEXT,
        attempts INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL
    )""",
    # After a reset by e-mail the old messages can't be decrypted with the new
    # keys. A member who can still read a message wraps its message key again
    # for the new keys of `recipient_id`; the server only stores that wrapped key.
    """CREATE TABLE IF NOT EXISTS message_key_shares (
        message_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        sharer_id TEXT NOT NULL,
        sharer_pub_ecdh TEXT NOT NULL,
        iv TEXT NOT NULL,
        k TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (message_id, recipient_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_key_shares_recipient ON message_key_shares(recipient_id)",
    # Voice calls in the browser. The audio goes directly between the browsers
    # (WebRTC); the server only knows who is called and who joined.
    """CREATE TABLE IF NOT EXISTS calls (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        started_by TEXT NOT NULL,
        started_at TEXT NOT NULL,
        answered_at TEXT,
        ended_at TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_calls_chat ON calls(chat_id, ended_at)",
    """CREATE TABLE IF NOT EXISTS call_participants (
        call_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('ringing', 'joined', 'left', 'declined', 'missed')),
        updated_at TEXT NOT NULL,
        seen_at TEXT NOT NULL,
        PRIMARY KEY (call_id, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_call_participants_user ON call_participants(user_id, state)",
    # Password reset links sent by e-mail. Only a hash of the token is stored.
    """CREATE TABLE IF NOT EXISTS password_resets (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT
    )""",
]

# Indexes on columns that are added by `_migrate_columns`.
LATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL",
]

USER_COLUMNS = {
    "auth_version": "INTEGER NOT NULL DEFAULT 0",
    "kdf_salt": "TEXT",
    "kdf_iterations": "INTEGER",
    "pub_ecdh": "TEXT",
    "pub_sign": "TEXT",
    "enc_private": "TEXT",
    "created_at": "TEXT",
    # Shown instead of the username; does not have to be unique.
    "display_name": "TEXT",
    # Last authenticated request, for "online" / "last seen".
    "last_seen": "TEXT",
    "show_last_seen": "INTEGER NOT NULL DEFAULT 1",
    # Authenticator app (TOTP): the active secret, one being set up, and the last
    # used time step so a code can't be used twice.
    "totp_secret": "TEXT",
    "totp_pending": "TEXT",
    "totp_last_step": "INTEGER NOT NULL DEFAULT 0",
}


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path):
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# Columns added after the first release of a table.
EXTRA_COLUMNS = {
    "users": USER_COLUMNS,
    # Remembers a friendship so unblocking restores it.
    "blocks": {"was_friend": "INTEGER NOT NULL DEFAULT 0"},
    "chat_members": {
        "delivered_seq": "INTEGER NOT NULL DEFAULT 0",
        # Per member: chat pinned to the top / moved to the archive.
        "pinned": "INTEGER NOT NULL DEFAULT 0",
        "archived": "INTEGER NOT NULL DEFAULT 0",
        # Reset by e-mail: messages up to reset_seq were encrypted for the old
        # keys and wait for another member to share them again (0 = nothing
        # waiting). reset_cleared_seq is what the member had cleared before.
        "reset_seq": "INTEGER NOT NULL DEFAULT 0",
        "reset_cleared_seq": "INTEGER NOT NULL DEFAULT 0",
    },
    "messages": {
        "edited_at": "TEXT",
        # Silent messages (e.g. reactions) don't count as unread or as the last message.
        "silent": "INTEGER NOT NULL DEFAULT 0",
        # Disappearing messages are deleted by the server after this time.
        "expires_at": "TEXT",
    },
    # Disappearing messages timer of the chat, 0 = off.
    "chats": {"disappear_seconds": "INTEGER NOT NULL DEFAULT 0"},
}


def _migrate_columns(conn):
    for table, columns in EXTRA_COLUMNS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column, definition in columns.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _mark_earlier_key_resets(conn):
    """Once: resets by e-mail from before reset_seq existed also wait for their
    history to be shared again. Their chats were hidden up to the reset."""
    if get_meta(conn, "key_resets_marked"):
        return
    resets = conn.execute(
        "SELECT user_id, MAX(replaced_at) AS at FROM user_key_history GROUP BY user_id"
    ).fetchall()
    for reset in resets:
        members = conn.execute(
            "SELECT chat_id, joined_seq, cleared_seq FROM chat_members WHERE user_id = ? AND reset_seq = 0",
            (reset["user_id"],),
        ).fetchall()
        for member in members:
            until = conn.execute(
                """SELECT COALESCE(MAX(seq), 0) AS s FROM messages
                   WHERE chat_id = ? AND kind != 'system' AND created_at <= ?""",
                (member["chat_id"], reset["at"]),
            ).fetchone()["s"]
            # Still hidden since the reset, and there is something to share.
            if member["cleared_seq"] < until or not has_encrypted_between(
                conn, member["chat_id"], member["joined_seq"], until
            ):
                continue
            conn.execute(
                "UPDATE chat_members SET reset_seq = ?, reset_cleared_seq = 0 WHERE chat_id = ? AND user_id = ?",
                (until, member["chat_id"], reset["user_id"]),
            )
    set_meta(conn, "key_resets_marked", "1")


def has_encrypted_between(conn, chat_id, after_seq, until_seq):
    return (
        conn.execute(
            """SELECT 1 FROM messages WHERE chat_id = ? AND kind = 'e2e' AND deleted = 0
               AND seq > ? AND seq <= ? LIMIT 1""",
            (chat_id, after_seq, until_seq),
        ).fetchone()
        is not None
    )


def init_schema(conn):
    for statement in SCHEMA:
        conn.execute(statement)
    _migrate_columns(conn)
    _mark_earlier_key_resets(conn)
    for statement in LATE_INDEXES:
        conn.execute(statement)
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)"
        )
    except sqlite3.IntegrityError:
        # Old installations may contain usernames that only differ in case.
        # Uniqueness is still enforced on registration.
        pass
    conn.commit()


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def server_secret(conn):
    """Persistent random secret used e.g. to derive fake KDF salts for unknown users."""
    secret = get_meta(conn, "server_secret")
    if not secret:
        secret = secrets.token_hex(32)
        set_meta(conn, "server_secret", secret)
        conn.commit()
    return secret


@contextlib.contextmanager
def write_transaction(conn):
    """Serialises writers so revision numbers are strictly increasing."""
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def next_rev(conn):
    row = conn.execute("SELECT COALESCE(MAX(rev), 0) + 1 AS r FROM messages").fetchone()
    return row["r"]
