CREATE TABLE IF NOT EXISTS blocks (
        blocker_id TEXT NOT NULL,
        blocked_id TEXT NOT NULL,
        created_at TEXT NOT NULL, was_friend INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (blocker_id, blocked_id)
    );

CREATE TABLE IF NOT EXISTS call_participants (
        call_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('ringing', 'joined', 'left', 'declined', 'missed')),
        updated_at TEXT NOT NULL,
        seen_at TEXT NOT NULL,
        PRIMARY KEY (call_id, user_id)
    );

CREATE TABLE IF NOT EXISTS call_signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id TEXT NOT NULL,
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('offer', 'answer')),
        data TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS calls (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        started_by TEXT NOT NULL,
        started_at TEXT NOT NULL,
        answered_at TEXT,
        ended_at TEXT
    );

CREATE TABLE IF NOT EXISTS chat_members (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        joined_at TEXT NOT NULL,
        joined_seq INTEGER NOT NULL DEFAULT 0,
        cleared_seq INTEGER NOT NULL DEFAULT 0,
        last_read_seq INTEGER NOT NULL DEFAULT 0,
        hidden INTEGER NOT NULL DEFAULT 0, delivered_seq INTEGER NOT NULL DEFAULT 0, pinned INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0, reset_seq INTEGER NOT NULL DEFAULT 0, reset_cleared_seq INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, user_id)
    );

CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK (type IN ('dm', 'group')),
        name TEXT,
        owner_id TEXT,
        dm_key TEXT UNIQUE,
        created_at TEXT NOT NULL,
        last_activity TEXT NOT NULL
    , disappear_seconds INTEGER NOT NULL DEFAULT 0, avatar_updated_at TEXT);

CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        uploader_id TEXT NOT NULL,
        message_id TEXT,
        size INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS friend_invites (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS friend_requests (
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (from_id, to_id)
    );

CREATE TABLE IF NOT EXISTS friendships (
        user_a TEXT NOT NULL,
        user_b TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_a, user_b)
    );

CREATE TABLE IF NOT EXISTS message_key_shares (
        message_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        sharer_id TEXT NOT NULL,
        sharer_pub_ecdh TEXT NOT NULL,
        iv TEXT NOT NULL,
        k TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (message_id, recipient_id)
    );

CREATE TABLE IF NOT EXISTS messages (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        chat_id TEXT NOT NULL,
        sender_id TEXT,
        kind TEXT NOT NULL CHECK (kind IN ('e2e', 'legacy', 'system')),
        payload TEXT,
        created_at TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        rev INTEGER NOT NULL DEFAULT 0
    , edited_at TEXT, silent INTEGER NOT NULL DEFAULT 0, expires_at TEXT);

CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    );

CREATE TABLE IF NOT EXISTS muted_users (
        user_id TEXT NOT NULL,
        muted_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, muted_id)
    );

CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        transports TEXT,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT
    );

CREATE TABLE IF NOT EXISTS password_resets (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT
    );

CREATE TABLE IF NOT EXISTS pinned_messages (
        chat_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        pinned_by TEXT NOT NULL,
        pinned_at TEXT NOT NULL,
        PRIMARY KEY (chat_id, message_id)
    );

CREATE TABLE IF NOT EXISTS receipts (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('delivered', 'read')),
        seq INTEGER NOT NULL,
        at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS recovery_codes (
        user_id TEXT NOT NULL,
        slot TEXT NOT NULL,
        kdf_salt TEXT NOT NULL,
        auth_hash TEXT NOT NULL,
        enc_private TEXT NOT NULL,
        created_at TEXT NOT NULL,
        used_at TEXT,
        PRIMARY KEY (user_id, slot)
    );

CREATE TABLE IF NOT EXISTS scheduled_messages (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        member_ids TEXT NOT NULL,
        sender_sign_key TEXT NOT NULL,
        send_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS twofa_challenges (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        challenge TEXT,
        attempts INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS user_key_history (
        user_id TEXT NOT NULL,
        pub_ecdh TEXT NOT NULL,
        pub_sign TEXT NOT NULL,
        replaced_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255),
        username VARCHAR(255),
        passwd TEXT
    , auth_version INTEGER NOT NULL DEFAULT 0, kdf_salt TEXT, kdf_iterations INTEGER, pub_ecdh TEXT, pub_sign TEXT, enc_private TEXT, created_at TEXT, display_name TEXT, last_seen TEXT, show_last_seen INTEGER NOT NULL DEFAULT 1, totp_secret TEXT, totp_pending TEXT, totp_last_step INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS user_avatars (
  user_id TEXT PRIMARY KEY,
  image BLOB NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_blobs (
  id TEXT PRIMARY KEY,
  data BLOB NOT NULL
);