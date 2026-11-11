use anyhow::{Context, Result};
use sqlx::{
    Row, SqlitePool, sqlite::SqliteConnectOptions, sqlite::SqliteJournalMode,
    sqlite::SqlitePoolOptions,
};
use std::{collections::HashSet, fs, path::Path, str::FromStr, time::Duration};
use uuid::Uuid;

pub async fn connect(path: &Path) -> Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(15));
    let pool = SqlitePoolOptions::new()
        .max_connections(16)
        .connect_with(options)
        .await
        .context("connect to SQLite database")?;

    sqlx::raw_sql(include_str!("../migrations/0001_existing_schema.sql"))
        .execute(&pool)
        .await
        .context("create base schema")?;
    ensure_columns(
        &pool,
        "users",
        &[
            ("auth_version", "INTEGER NOT NULL DEFAULT 0"),
            ("kdf_salt", "TEXT"),
            ("kdf_iterations", "INTEGER"),
            ("pub_ecdh", "TEXT"),
            ("pub_sign", "TEXT"),
            ("enc_private", "TEXT"),
            ("created_at", "TEXT"),
            ("display_name", "TEXT"),
            ("last_seen", "TEXT"),
            ("show_last_seen", "INTEGER NOT NULL DEFAULT 1"),
            ("totp_secret", "TEXT"),
            ("totp_pending", "TEXT"),
            ("totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
        ],
    )
    .await?;
    ensure_columns(
        &pool,
        "blocks",
        &[("was_friend", "INTEGER NOT NULL DEFAULT 0")],
    )
    .await?;
    ensure_columns(
        &pool,
        "chat_members",
        &[
            ("delivered_seq", "INTEGER NOT NULL DEFAULT 0"),
            ("pinned", "INTEGER NOT NULL DEFAULT 0"),
            ("archived", "INTEGER NOT NULL DEFAULT 0"),
            ("reset_seq", "INTEGER NOT NULL DEFAULT 0"),
            ("reset_cleared_seq", "INTEGER NOT NULL DEFAULT 0"),
        ],
    )
    .await?;
    ensure_columns(
        &pool,
        "messages",
        &[
            ("edited_at", "TEXT"),
            ("silent", "INTEGER NOT NULL DEFAULT 0"),
            ("expires_at", "TEXT"),
        ],
    )
    .await?;
    ensure_columns(
        &pool,
        "chats",
        &[
            ("disappear_seconds", "INTEGER NOT NULL DEFAULT 0"),
            ("avatar_updated_at", "TEXT"),
        ],
    )
    .await?;

    sqlx::raw_sql(include_str!("../migrations/0002_indexes.sql"))
        .execute(&pool)
        .await
        .context("create indexes")?;
    sqlx::raw_sql(include_str!("../migrations/0003_email_uniqueness.sql"))
        .execute(&pool)
        .await
        .context("enforce email uniqueness")?;
    // Older installations can contain names that differ only by case. Keep
    // their data intact and enforce case-insensitive uniqueness on new users.
    let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)")
        .execute(&pool).await;
    sqlx::query("CREATE TABLE IF NOT EXISTS user_avatars (user_id TEXT PRIMARY KEY, image BLOB NOT NULL, updated_at TEXT NOT NULL)")
        .execute(&pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS group_avatars (chat_id TEXT PRIMARY KEY, image BLOB NOT NULL, updated_at TEXT NOT NULL)")
        .execute(&pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS file_blobs (id TEXT PRIMARY KEY, data BLOB NOT NULL)")
        .execute(&pool)
        .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS user_settings (user_id TEXT PRIMARY KEY, show_last_seen INTEGER NOT NULL DEFAULT 1)")
        .execute(&pool).await?;
    sqlx::query("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1')")
        .execute(&pool)
        .await?;
    Ok(pool)
}

async fn ensure_columns(pool: &SqlitePool, table: &str, columns: &[(&str, &str)]) -> Result<()> {
    // Table names and definitions come only from the static migration list above.
    let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(pool)
        .await?;
    let existing: std::collections::HashSet<String> = rows
        .iter()
        .filter_map(|row| sqlx::Row::try_get::<String, _>(row, "name").ok())
        .collect();
    for (name, definition) in columns {
        if !existing.contains(*name) {
            sqlx::query(&format!(
                "ALTER TABLE {table} ADD COLUMN {name} {definition}"
            ))
            .execute(pool)
            .await
            .with_context(|| format!("add {table}.{name}"))?;
        }
    }
    Ok(())
}

pub async fn ensure_server_secret(pool: &SqlitePool) -> Result<()> {
    let secret =
        sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key='server_secret'")
            .fetch_optional(pool)
            .await?;
    if secret.is_none() {
        let secret = rand::random::<[u8; 32]>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        sqlx::query("INSERT OR IGNORE INTO meta(key,value) VALUES('server_secret',?)")
            .bind(secret)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Imports the previous JSON/per-chat SQLite format once, without deleting the
/// original files. Data remains end-to-end encrypted exactly as before.
pub async fn import_legacy(pool: &SqlitePool, data_dir: &Path) -> Result<()> {
    let done =
        sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key='legacy_files_migrated'")
            .fetch_optional(pool)
            .await?;
    if done.is_some() {
        return Ok(());
    }
    let user_ids: HashSet<String> = sqlx::query_scalar("SELECT id FROM users")
        .fetch_all(pool)
        .await?
        .into_iter()
        .collect();
    let now = now_iso();
    let mut tx = pool.begin().await?;
    let user_root = data_dir.join("user_data");
    {
        for entry in legacy_entries(&user_root)? {
            let user_id = entry.file_name().to_string_lossy().into_owned();
            if !user_ids.contains(&user_id) {
                continue;
            }
            if let Some(value) = read_json(&entry.path().join("friends.json"))?
                && let Some(friends) = value.get("friends").and_then(serde_json::Value::as_array)
            {
                for friend in friends.iter().filter_map(serde_json::Value::as_str) {
                    if user_ids.contains(friend) && friend != user_id {
                        let (a, b) = if user_id.as_str() < friend {
                            (user_id.as_str(), friend)
                        } else {
                            (friend, user_id.as_str())
                        };
                        sqlx::query("INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,?)")
                                .bind(a).bind(b).bind(&now).execute(&mut *tx).await?;
                    }
                }
            }
            if let Some(value) = read_json(&entry.path().join("pending_friends.json"))?
                && let Some(pending) = value.get("pending").and_then(serde_json::Value::as_array)
            {
                for from_id in pending.iter().filter_map(serde_json::Value::as_str) {
                    if user_ids.contains(from_id) && from_id != user_id {
                        sqlx::query("INSERT OR IGNORE INTO friend_requests(from_id,to_id,created_at) VALUES(?,?,?)")
                                .bind(from_id).bind(&user_id).bind(&now).execute(&mut *tx).await?;
                    }
                }
            }
        }
    }

    let chats_root = data_dir.join("chats");
    {
        for entry in legacy_entries(&chats_root)? {
            let old_chat_id = entry.file_name().to_string_lossy().into_owned();
            let Some(users) = read_json(&entry.path().join("users.json"))?.and_then(|v| {
                v.get("users")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
            }) else {
                continue;
            };
            if users.len() != 2 {
                continue;
            }
            let Some(first) = users[0].as_str() else {
                continue;
            };
            let Some(second) = users[1].as_str() else {
                continue;
            };
            if first == second || !user_ids.contains(first) || !user_ids.contains(second) {
                continue;
            }
            let (a, b) = if first < second {
                (first, second)
            } else {
                (second, first)
            };
            let dm_key = format!("{a}:{b}");
            let found = sqlx::query("SELECT 1 FROM chats WHERE dm_key=?")
                .bind(&dm_key)
                .fetch_optional(&mut *tx)
                .await?;
            if found.is_some() {
                continue;
            }
            let chat_id = Uuid::parse_str(&old_chat_id)
                .map(|_| old_chat_id.clone())
                .unwrap_or_else(|_| Uuid::new_v4().to_string());
            let messages = legacy_messages(&entry.path().join("history.db")).await?;
            let last_activity = messages
                .last()
                .map(|m| legacy_timestamp(&m.timestamp))
                .unwrap_or_else(|| now.clone());
            sqlx::query("INSERT INTO chats(id,type,name,owner_id,dm_key,created_at,last_activity) VALUES(?,'dm',NULL,NULL,?,?,?)")
                .bind(&chat_id).bind(&dm_key).bind(&now).bind(&last_activity).execute(&mut *tx).await?;
            for user_id in [a, b] {
                sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at) VALUES(?,?,'member',?)")
                    .bind(&chat_id).bind(user_id).bind(&now).execute(&mut *tx).await?;
            }
            for message in messages {
                if message
                    .sender_id
                    .as_deref()
                    .is_none_or(|sender| sender != a && sender != b)
                {
                    continue;
                }
                let id = message
                    .id
                    .filter(|id| !id.is_empty())
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                let payload =
                    serde_json::json!({"text":message.content.unwrap_or_default()}).to_string();
                let inserted=sqlx::query("INSERT OR IGNORE INTO messages(id,chat_id,sender_id,kind,payload,created_at) VALUES(?,?,?,'legacy',?,?)")
                    .bind(id).bind(&chat_id).bind(message.sender_id).bind(payload).bind(legacy_timestamp(&message.timestamp)).execute(&mut *tx).await?;
                if inserted.rows_affected() > 0 {
                    let seq = inserted.last_insert_rowid();
                    sqlx::query("UPDATE messages SET rev=seq WHERE seq=?")
                        .bind(seq)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }
    }
    sqlx::query("INSERT INTO meta(key,value) VALUES('legacy_files_migrated',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct LegacyMessage {
    id: Option<String>,
    sender_id: Option<String>,
    content: Option<String>,
    timestamp: String,
}

async fn legacy_messages(path: &Path) -> Result<Vec<LegacyMessage>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    if metadata.len() == 0 {
        return Ok(Vec::new());
    }
    let options = SqliteConnectOptions::new().filename(path).read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("open legacy history {}", path.display()))?;
    let rows =
        sqlx::query("SELECT id,sender_id,content,timestamp FROM messages ORDER BY timestamp ASC")
            .fetch_all(&pool)
            .await;
    pool.close().await;
    let rows = rows.with_context(|| format!("read legacy history {}", path.display()))?;
    rows.into_iter()
        .map(|row| {
            Ok(LegacyMessage {
                id: row.try_get("id")?,
                sender_id: row.try_get("sender_id")?,
                content: row.try_get("content")?,
                timestamp: row.try_get("timestamp")?,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn legacy_entries(path: &Path) -> Result<Vec<fs::DirEntry>> {
    match fs::read_dir(path) {
        Ok(entries) => entries
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("read legacy directory {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => {
            Err(error).with_context(|| format!("read legacy directory {}", path.display()))
        }
    }
}

fn optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read legacy file {}", path.display())),
    }
}

fn read_json(path: &Path) -> Result<Option<serde_json::Value>> {
    optional_file(path)?
        .map(|raw| {
            serde_json::from_slice(&raw)
                .with_context(|| format!("parse legacy JSON {}", path.display()))
        })
        .transpose()
}

fn legacy_timestamp(value: &str) -> String {
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .map(|dt| dt.and_utc().format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|_| now_iso())
}

/// Moves legacy avatar and attachment bytes into SQLite BLOB tables. Files are
/// retained as a backup; new uploads never touch the filesystem.
pub async fn migrate_binary_files(pool: &SqlitePool, data_dir: &Path) -> Result<()> {
    if sqlx::query("SELECT 1 FROM meta WHERE key='legacy_binary_files_migrated'")
        .fetch_optional(pool)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let users = sqlx::query_scalar::<_, String>("SELECT id FROM users")
        .fetch_all(&mut *tx)
        .await?;
    for user_id in users {
        let path = data_dir.join("user_data").join(&user_id).join("avatar.png");
        if let Some(bytes) = optional_file(&path)? {
            sqlx::query(
                "INSERT OR IGNORE INTO user_avatars(user_id,image,updated_at) VALUES(?,?,?)",
            )
            .bind(user_id)
            .bind(bytes)
            .bind(now_iso())
            .execute(&mut *tx)
            .await?;
        }
    }
    let groups = sqlx::query("SELECT id,avatar_updated_at FROM chats WHERE type='group'")
        .fetch_all(&mut *tx)
        .await?;
    for row in groups {
        let chat_id: String = row.try_get("id")?;
        let path = data_dir
            .join("group_avatars")
            .join(format!("{chat_id}.png"));
        if let Some(bytes) = optional_file(&path)? {
            let updated: Option<String> = row.try_get("avatar_updated_at").ok().flatten();
            sqlx::query(
                "INSERT OR IGNORE INTO group_avatars(chat_id,image,updated_at) VALUES(?,?,?)",
            )
            .bind(chat_id)
            .bind(bytes)
            .bind(updated.unwrap_or_else(now_iso))
            .execute(&mut *tx)
            .await?;
        }
    }
    let ids = sqlx::query_scalar::<_, String>("SELECT id FROM files")
        .fetch_all(&mut *tx)
        .await?;
    for id in ids {
        let path = data_dir.join("files").join(&id);
        if let Some(bytes) = optional_file(&path)? {
            sqlx::query("INSERT OR IGNORE INTO file_blobs(id,data) VALUES(?,?)")
                .bind(id)
                .bind(bytes)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query("INSERT INTO meta(key,value) VALUES('legacy_binary_files_migrated',?)")
        .bind(now_iso())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("seres-regression-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            // The fixture owns this unique, absolute directory beneath the OS temp directory.
            if self.0.is_absolute() && self.0.parent() == Some(std::env::temp_dir().as_path()) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    #[tokio::test]
    async fn failed_history_import_rolls_back_and_can_be_retried() {
        let fixture = Fixture::new();
        let pool = connect(&fixture.0.join("users.db")).await.unwrap();
        for id in ["alice", "bob"] {
            sqlx::query("INSERT INTO users(id,username) VALUES(?,?)")
                .bind(id)
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let chat = fixture.0.join("chats").join(Uuid::new_v4().to_string());
        fs::create_dir_all(&chat).unwrap();
        fs::write(chat.join("users.json"), r#"{"users":["alice","bob"]}"#).unwrap();
        fs::write(chat.join("history.db"), b"corrupt sqlite history").unwrap();
        assert!(import_legacy(&pool, &fixture.0).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chats")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert!(
            sqlx::query("SELECT 1 FROM meta WHERE key='legacy_files_migrated'")
                .fetch_optional(&pool)
                .await
                .unwrap()
                .is_none()
        );
        fs::remove_file(chat.join("history.db")).unwrap();
        let old = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(chat.join("history.db"))
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE messages(id TEXT, sender_id TEXT, content TEXT, timestamp TEXT); INSERT INTO messages VALUES('old-message','alice','hello','2025-01-01 12:00:00');")
            .execute(&old).await.unwrap();
        old.close().await;
        import_legacy(&pool, &fixture.0).await.unwrap();
        import_legacy(&pool, &fixture.0).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE id='old-message'")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn deleted_imported_group_avatar_stays_deleted_after_reconnect() {
        let fixture = Fixture::new();
        let database = fixture.0.join("users.db");
        let pool = connect(&database).await.unwrap();
        sqlx::query("INSERT INTO chats(id,type,created_at,last_activity) VALUES('group','group','now','now')")
            .execute(&pool).await.unwrap();
        fs::create_dir(fixture.0.join("group_avatars")).unwrap();
        fs::write(fixture.0.join("group_avatars/group.png"), b"legacy picture").unwrap();
        migrate_binary_files(&pool, &fixture.0).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM group_avatars")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        sqlx::query("DELETE FROM group_avatars WHERE chat_id='group'")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let pool = connect(&database).await.unwrap();
        migrate_binary_files(&pool, &fixture.0).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM group_avatars")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        assert!(fixture.0.join("group_avatars/group.png").exists());
        pool.close().await;
    }

    #[tokio::test]
    async fn concurrent_case_insensitive_email_claims_allow_only_one_account() {
        let fixture = Fixture::new();
        let pool = connect(&fixture.0.join("users.db")).await.unwrap();
        let (a, b) = tokio::join!(
            sqlx::query(
                "INSERT INTO users(id,username,email) VALUES('alice','alice','Shared@example.com')"
            )
            .execute(&pool),
            sqlx::query(
                "INSERT INTO users(id,username,email) VALUES('bob','bob','shared@example.com')"
            )
            .execute(&pool)
        );
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn email_constraints_preserve_existing_duplicates_but_block_new_claims() {
        let fixture = Fixture::new();
        let database = fixture.0.join("users.db");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&database)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../migrations/0001_existing_schema.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql("INSERT INTO users(id,username,email) VALUES('a','aaa','same@example.com'),('b','bbb','SAME@example.com');")
            .execute(&pool).await.unwrap();
        pool.close().await;
        let pool = connect(&database).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
        assert!(
            sqlx::query("INSERT INTO users(id,email) VALUES('c','same@example.com')")
                .execute(&pool)
                .await
                .is_err()
        );
        sqlx::query("INSERT INTO users(id,email) VALUES('c','other@example.com')")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            sqlx::query("UPDATE users SET email='same@example.com' WHERE id='c'")
                .execute(&pool)
                .await
                .is_err()
        );
        sqlx::query("UPDATE users SET email=email WHERE id='a'")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
}
