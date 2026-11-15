use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::collections::HashMap;
use uuid::Uuid;

const MAX_GROUP_MEMBERS: usize = 50;
const MAX_CIPHERTEXT_LEN: usize = 64 * 1024;
const MAX_FILES_PER_MESSAGE: usize = 10;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024 + 1024;

pub async fn scheduled_loop(pool: SqlitePool) {
    loop {
        if let Err(error) = deliver_due_messages(&pool).await {
            tracing::error!(%error, "scheduled message delivery failed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/chats", get(list_chats).post(create_chat))
        .route("/api/load_chats", get(list_chats))
        .route("/api/new_chat", post(new_chat_legacy))
        .route("/api/chats/{chat_id}", get(chat_details))
        .route(
            "/api/chats/{chat_id}/messages",
            get(get_chat_messages).post(post_message),
        )
        .route("/api/get_messages", get(get_messages_legacy))
        .route("/api/send_message", post(send_message_legacy))
        .route("/api/remove_chat", post(remove_chat_legacy))
        .route(
            "/api/chats/{chat_id}/messages/{message_id}/delete",
            post(delete_message),
        )
        .route(
            "/api/chats/{chat_id}/messages/{message_id}/edit",
            post(edit_message),
        )
        .route("/api/chats/{chat_id}/typing", post(set_typing))
        .route("/api/chats/{chat_id}/read", post(mark_read))
        .route("/api/chats/{chat_id}/members", post(add_member_route))
        .route(
            "/api/chats/{chat_id}/members/remove",
            post(remove_member_route),
        )
        .route("/api/chats/{chat_id}/rename", post(rename_group))
        .route("/api/chats/{chat_id}/leave", post(delete_chat))
        .route("/api/chats/{chat_id}/delete", post(delete_chat))
        .route(
            "/api/chats/{chat_id}/messages/{message_id}",
            get(single_message),
        )
        .route(
            "/api/chats/{chat_id}/messages/{message_id}/info",
            get(message_info),
        )
        .route("/api/chats/{chat_id}/pins", post(pin_message))
        .route("/api/chats/{chat_id}/prefs", post(chat_prefs))
        .route("/api/chats/{chat_id}/disappearing", post(set_disappearing))
        .route(
            "/api/chats/{chat_id}/scheduled",
            get(scheduled_list).post(schedule_message),
        )
        .route(
            "/api/chats/{chat_id}/scheduled/{message_id}",
            axum::routing::delete(cancel_scheduled),
        )
        .route("/api/chats/{chat_id}/files", post(upload_file))
        .route("/api/chats/{chat_id}/files/{file_id}", get(download_file))
        .route(
            "/api/chats/{chat_id}/history/{user_id}",
            post(share_history),
        )
        .layer(DefaultBodyLimit::max(MAX_FILE_BYTES + 64 * 1024))
}

async fn list_chats(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if purge_expired(&state.db).await.is_err() {
        return db_error();
    }
    let rows=sqlx::query("SELECT c.*,m.role,m.joined_seq,m.cleared_seq,m.last_read_seq,m.hidden,m.pinned,m.archived,m.delivered_seq,m.reset_seq,m.reset_cleared_seq FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE m.user_id=? AND m.hidden=0 ORDER BY c.last_activity DESC").bind(&me.id).fetch_all(&state.db).await;
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let mut chats = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id").unwrap_or_default();
        let _ = advance_receipt(
            &state.db,
            &id,
            &me.id,
            "delivered",
            max_seq(&state.db, &id).await.unwrap_or(0),
        )
        .await;
        match chat_summary(&state, &row, &me.id).await {
            Ok(v) => chats.push(v),
            Err(_) => return db_error(),
        }
    }
    json_ok(json!({"chats":chats})).into_response()
}

async fn create_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if body.get("type").and_then(Value::as_str).unwrap_or("dm") == "dm" {
        let username = body
            .get("username")
            .or_else(|| body.get("friend_username"))
            .and_then(Value::as_str)
            .filter(|v| !v.trim().is_empty());
        let Some(username) = username else {
            return error("Missing or invalid 'username'", StatusCode::BAD_REQUEST);
        };
        let other = match sqlx::query("SELECT id FROM users WHERE username=? COLLATE NOCASE")
            .bind(username.trim())
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(r)) => r.try_get::<String, _>("id").unwrap_or_default(),
            Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
            Err(_) => return db_error(),
        };
        return open_dm(&state, &me.id, &other).await;
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.chars().count() <= 64);
    let Some(name) = name else {
        return error(
            "Group name must be 1-64 characters",
            StatusCode::BAD_REQUEST,
        );
    };
    let Some(usernames) = body.get("usernames").and_then(Value::as_array) else {
        return error(
            "Pick at least one friend for the group",
            StatusCode::BAD_REQUEST,
        );
    };
    if usernames.is_empty() {
        return error(
            "Pick at least one friend for the group",
            StatusCode::BAD_REQUEST,
        );
    }
    let mut members = Vec::new();
    for item in usernames {
        let Some(username) = item.as_str() else {
            return error("A member name is invalid", StatusCode::BAD_REQUEST);
        };
        let row = sqlx::query("SELECT id FROM users WHERE username=? COLLATE NOCASE")
            .bind(username.trim())
            .fetch_optional(&state.db)
            .await;
        let id = match row {
            Ok(Some(r)) => r.try_get::<String, _>("id").unwrap_or_default(),
            _ => {
                return error(
                    format!("{username} is not your friend"),
                    StatusCode::BAD_REQUEST,
                );
            }
        };
        if id == me.id {
            continue;
        }
        if !are_friends(&state.db, &me.id, &id).await.unwrap_or(false) {
            return error(
                format!("{username} is not your friend"),
                StatusCode::BAD_REQUEST,
            );
        }
        if !members.contains(&id) {
            members.push(id)
        }
    }
    if members.is_empty() || members.len() + 1 > MAX_GROUP_MEMBERS {
        return error(
            format!("A group needs 2-{MAX_GROUP_MEMBERS} members"),
            StatusCode::BAD_REQUEST,
        );
    }
    let chat_id = Uuid::new_v4().to_string();
    let now = now();
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES(?,'group',?,?,?,?)").bind(&chat_id).bind(name).bind(&me.id).bind(&now).bind(&now).execute(&mut *tx).await.is_err(){return db_error()}
    for (uid, role) in
        std::iter::once((&me.id, "owner")).chain(members.iter().map(|id| (id, "member")))
    {
        if insert_member(&mut tx, &chat_id, uid, role).await.is_err() {
            return db_error();
        }
    }
    if system_message(
        &mut tx,
        &chat_id,
        "created",
        json!({"actor":me.display_name,"name":name}),
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"chat_id":chat_id,"message":"Group created successfully!"})).into_response()
}

async fn new_chat_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty());
    let Some(name) = name else {
        return error("Missing or invalid 'username'", StatusCode::BAD_REQUEST);
    };
    let other = match sqlx::query_scalar::<_, String>(
        "SELECT id FROM users WHERE username=? COLLATE NOCASE",
    )
    .bind(name.trim())
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    open_dm(&state, &me.id, &other).await
}

async fn open_dm(state: &AppState, me: &str, other: &str) -> axum::response::Response {
    if me == other {
        return error("Cannot create chat with yourself", StatusCode::BAD_REQUEST);
    }
    if is_blocked(&state.db, me, other).await.unwrap_or(true) {
        return error("Cannot create chat with this user", StatusCode::BAD_REQUEST);
    }
    let (a, b) = pair(me, other);
    let key = format!("{a}:{b}");
    if let Some(row) = sqlx::query("SELECT id FROM chats WHERE dm_key=?")
        .bind(&key)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
    {
        let id: String = row.try_get("id").unwrap_or_default();
        let mut tx = match state.db.begin().await {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
        if sqlx::query("INSERT OR IGNORE INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,last_read_seq) SELECT ?,?, 'member', ?, COALESCE(MAX(seq),0),0,COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?").bind(&id).bind(me).bind(now()).bind(&id).execute(&mut *tx).await.is_err()||sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=? AND user_id=?").bind(&id).bind(me).execute(&mut *tx).await.is_err()||tx.commit().await.is_err(){return db_error()}
        return json_ok(json!({"chat_id":id,"message":"Chat already exists","existing":true}))
            .into_response();
    }
    if !are_friends(&state.db, me, other).await.unwrap_or(false) {
        return error(
            "Cannot create chat with a user who is not your friend",
            StatusCode::BAD_REQUEST,
        );
    }
    let id = Uuid::new_v4().to_string();
    let now = now();
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query(
        "INSERT INTO chats(id,type,dm_key,created_at,last_activity) VALUES(?,'dm',?,?,?)",
    )
    .bind(&id)
    .bind(key)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .is_err()
        || insert_member(&mut tx, &id, me, "member").await.is_err()
        || insert_member(&mut tx, &id, other, "member").await.is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"chat_id":id,"message":"Chat created successfully!"})).into_response()
}

async fn chat_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let row = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    match chat_summary(&state, &row, &me.id).await {
        Ok(mut chat) => {
            let members=sqlx::query("SELECT u.id,u.username,u.display_name,u.pub_ecdh,u.pub_sign,m.role,m.joined_seq,m.reset_seq,m.reset_cleared_seq FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? ORDER BY m.joined_at,u.username COLLATE NOCASE").bind(&chat_id).fetch_all(&state.db).await;
            let members = match members {
                Ok(v) => v,
                Err(_) => return db_error(),
            };
            let member_ids = members
                .iter()
                .filter_map(|m| m.try_get::<String, _>("id").ok())
                .collect::<Vec<_>>();
            let history = match previous_key_history(&state.db, &member_ids).await {
                Ok(v) => v,
                Err(_) => return db_error(),
            };
            chat["members"] = Value::Array(members.iter().map(|m| {
                let id=m.try_get::<String,_>("id").unwrap_or_default();
                json!({"id":id,"username":m.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(m),"pub_ecdh":m.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":m.try_get::<Option<String>,_>("pub_sign").ok().flatten(),"previous_keys":history.get(&id).cloned().unwrap_or_default(),"role":m.try_get::<String,_>("role").unwrap_or_default(),"history_reset":history_reset(m)})
            }).collect());
            chat["owner_id"] = row
                .try_get::<Option<String>, _>("owner_id")
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null);
            chat["pins"] = match chat_pins(
                &state.db,
                &chat_id,
                number(&row, "joined_seq").max(number(&row, "cleared_seq")),
            )
            .await
            {
                Ok(v) => json!(v),
                Err(_) => return db_error(),
            };
            json_ok(json!({"chat":chat})).into_response()
        }
        Err(_) => db_error(),
    }
}

async fn get_chat_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    messages_response(&state, &headers, &chat_id, &query).await
}
async fn get_messages_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let id = query.get("chat_id").cloned().unwrap_or_default();
    messages_response(&state, &headers, &id, &query).await
}
async fn send_message_legacy() -> axum::response::Response {
    error(
        "This client is outdated. Please reload the page to use encrypted messaging.",
        StatusCode::GONE,
    )
}
async fn remove_chat_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let Some(chat_id) = body
        .get("chat_id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64)
    else {
        return error("Missing or invalid 'chat_id'", StatusCode::BAD_REQUEST);
    };
    delete_chat_for(&state, &me, chat_id).await
}
async fn messages_response(
    state: &AppState,
    headers: &HeaderMap,
    chat_id: &str,
    query: &HashMap<String, String>,
) -> axum::response::Response {
    let me = match user(state, headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let limit = query
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    if purge_expired(&state.db).await.is_err() {
        return db_error();
    }
    let base = "SELECT m.*,u.username AS sender,u.display_name AS sender_display FROM messages m LEFT JOIN users u ON u.id=m.sender_id";
    let rows = if let Some(rev) = query.get("since_rev") {
        let rev = rev.parse::<i64>().unwrap_or(0);
        sqlx::query(&format!(
            "{base} WHERE m.chat_id=? AND m.seq>? AND m.rev>? ORDER BY m.rev ASC LIMIT ?"
        ))
        .bind(chat_id)
        .bind(floor)
        .bind(rev)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        let before = query
            .get("before_seq")
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|v| *v != 0)
            .unwrap_or(i64::MAX);
        sqlx::query(&format!(
            "{base} WHERE m.chat_id=? AND m.seq>? AND m.seq<? ORDER BY m.seq DESC LIMIT ?"
        ))
        .bind(chat_id)
        .bind(floor)
        .bind(before)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map(|mut v| {
            v.reverse();
            v
        })
    };
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if let Some(max) = rows.iter().map(|r| number(r, "seq")).max()
        && advance_receipt(&state.db, chat_id, &me.id, "delivered", max)
            .await
            .is_err()
    {
        return db_error();
    }
    let messages = rows.iter().map(serialize_message).collect::<Vec<_>>();
    let messages = match add_shares(&state.db, messages, &me.id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let receipts = member_receipts(&state.db, chat_id, &me.id)
        .await
        .ok()
        .flatten();
    let typing = typing_values(state, chat_id, &me.id).await;
    json_ok(json!({"messages":messages,"has_more":rows.len() as i64==limit,"typing":typing,"receipts":receipts})).into_response()
}

async fn post_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let id = body
        .get("id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64);
    let Some(id) = id else {
        return error("Missing or invalid 'id'", StatusCode::BAD_REQUEST);
    };
    if Uuid::parse_str(id).is_err() {
        return error("Invalid message id", StatusCode::BAD_REQUEST);
    }
    if state.rate_limited(format!("send:{}", me.id), 30, 10) {
        return error(
            "You are sending messages too fast",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let members = match member_ids(&state.db, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm")
        && let Some(other) = members.iter().find(|v| *v != &me.id)
        && is_blocked(&state.db, &me.id, other).await.unwrap_or(true)
    {
        return error(
            "You can't send messages to this chat",
            StatusCode::FORBIDDEN,
        );
    }
    let Some(payload) = body.get("payload") else {
        return error("Unsupported message format", StatusCode::BAD_REQUEST);
    };
    if let Some(problem) = validate_envelope(payload, &members) {
        let status = if problem.contains("members") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        return error(problem, status);
    }
    let silent = body.get("silent").and_then(Value::as_bool) == Some(true);
    let files = body.get("files").cloned().unwrap_or(json!([]));
    let Some(files) = files.as_array() else {
        return error("Invalid files", StatusCode::BAD_REQUEST);
    };
    if files.len() > MAX_FILES_PER_MESSAGE
        || files
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.len() > 64))
    {
        return error("Invalid files", StatusCode::BAD_REQUEST);
    }
    let expires = number(&chat, "disappear_seconds");
    let expires_at = (expires > 0).then(|| {
        (chrono::Utc::now() + chrono::Duration::seconds(expires))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    });
    let now = now();
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    for f in files {
        let Some(fid) = f.as_str() else {
            return error("Invalid files", StatusCode::BAD_REQUEST);
        };
        if sqlx::query("UPDATE files SET message_id=? WHERE id=? AND chat_id=? AND uploader_id=? AND message_id IS NULL").bind(id).bind(fid).bind(&chat_id).bind(&me.id).execute(&mut *tx).await.map(|r|r.rows_affected()).unwrap_or(0)==0{return error("Attachment not found, please upload it again",StatusCode::BAD_REQUEST)}
    }
    let rev = match next_rev(&mut tx).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let result=sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev,silent,expires_at) VALUES(?,?,?,'e2e',?,?,?,?,?)").bind(id).bind(&chat_id).bind(&me.id).bind(payload.to_string()).bind(&now).bind(rev).bind(i64::from(silent)).bind(expires_at).execute(&mut *tx).await;
    let result = match result {
        Ok(v) => v,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return error("Duplicate message id", StatusCode::CONFLICT);
        }
        Err(_) => return db_error(),
    };
    let seq = result.last_insert_rowid();
    if !silent
        && (sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
            .bind(&now)
            .bind(&chat_id)
            .execute(&mut *tx)
            .await
            .is_err()
            || sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=?")
                .bind(&chat_id)
                .execute(&mut *tx)
                .await
                .is_err())
    {
        return db_error();
    }
    if sqlx::query(
        "UPDATE chat_members SET last_read_seq=?,delivered_seq=? WHERE chat_id=? AND user_id=?",
    )
    .bind(seq)
    .bind(seq)
    .bind(&chat_id)
    .bind(&me.id)
    .execute(&mut *tx)
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    state.set_typing(chat_id, me.id, false);
    json_ok(json!({"message":"Message sent successfully!","seq":seq,"rev":rev})).into_response()
}

async fn delete_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let rev = match next_rev(&mut tx).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let result=sqlx::query("UPDATE messages SET deleted=1,payload=NULL,rev=? WHERE id=? AND chat_id=? AND sender_id=? AND deleted=0").bind(rev).bind(&message_id).bind(&chat_id).bind(&me.id).execute(&mut *tx).await;
    let rows = match result {
        Ok(v) => v.rows_affected(),
        Err(_) => return db_error(),
    };
    if rows > 0
        && forget_message_data(&mut tx, &chat_id, &message_id)
            .await
            .is_err()
    {
        return db_error();
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    if rows == 0 {
        return error("Message not found", StatusCode::NOT_FOUND);
    }
    json_ok(json!({"message":"Message deleted"})).into_response()
}
async fn edit_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let members = match member_ids(&state.db, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let Some(payload) = body.get("payload") else {
        return error("Unsupported message format", StatusCode::BAD_REQUEST);
    };
    if let Some(problem) = validate_envelope(payload, &members) {
        let status = if problem.contains("members") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        return error(problem, status);
    };
    let _ = chat;
    let now = now();
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let rev = match next_rev(&mut tx).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let result=sqlx::query("UPDATE messages SET payload=?,edited_at=?,rev=? WHERE id=? AND chat_id=? AND sender_id=? AND kind='e2e' AND deleted=0").bind(payload.to_string()).bind(now).bind(rev).bind(message_id).bind(&chat_id).bind(&me.id).execute(&mut *tx).await;
    let rows = match result {
        Ok(v) => v.rows_affected(),
        Err(_) => return db_error(),
    };
    if tx.commit().await.is_err() {
        return db_error();
    }
    if rows == 0 {
        return error("Message not found", StatusCode::NOT_FOUND);
    }
    json_ok(json!({"message":"Message edited"})).into_response()
}

async fn set_typing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    state.set_typing(
        chat_id,
        me.id,
        body.get("typing").and_then(Value::as_bool) != Some(false),
    );
    json_ok(json!({})).into_response()
}
async fn mark_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    let Some(seq) = body.get("seq").and_then(Value::as_i64) else {
        return error("Invalid seq", StatusCode::BAD_REQUEST);
    };
    let seq = seq.min(max_seq(&state.db, &chat_id).await.unwrap_or(0));
    match advance_receipt(&state.db, &chat_id, &me.id, "read", seq).await {
        Ok(_) => json_ok(json!({})).into_response(),
        Err(_) => db_error(),
    }
}

async fn add_member_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return error("Only possible in groups", StatusCode::BAD_REQUEST);
    }
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty());
    let Some(name) = name else {
        return error("Missing or invalid 'username'", StatusCode::BAD_REQUEST);
    };
    let other = match sqlx::query(
        "SELECT id,username,display_name FROM users WHERE username=? COLLATE NOCASE",
    )
    .bind(name.trim())
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let other_id: String = other.try_get("id").unwrap_or_default();
    if !are_friends(&state.db, &me.id, &other_id)
        .await
        .unwrap_or(false)
    {
        return error("You can only add your friends", StatusCode::BAD_REQUEST);
    }
    if membership(&state.db, &chat_id, &other_id)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return error("Already in the group", StatusCode::BAD_REQUEST);
    }
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chat_members WHERE chat_id=?")
        .bind(&chat_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
    if count >= MAX_GROUP_MEMBERS as i64 {
        return error("The group is full", StatusCode::BAD_REQUEST);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if insert_member(&mut tx, &chat_id, &other_id, "member")
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "added",
            json!({"actor":me.display_name,"target":display_name(&other)}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Member added"})).into_response()
}
async fn remove_member_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return error("Only possible in groups", StatusCode::BAD_REQUEST);
    }
    if chat.try_get::<String, _>("role").ok().as_deref() != Some("owner") {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    let other = match target_member(&state.db, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if other.0 == me.id {
        return error("Use 'leave group' instead", StatusCode::BAD_REQUEST);
    }
    if membership(&state.db, &chat_id, &other.0)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Not a member", StatusCode::BAD_REQUEST);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM chat_members WHERE chat_id=? AND user_id=?")
        .bind(&chat_id)
        .bind(&other.0)
        .execute(&mut *tx)
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "removed",
            json!({"actor":me.display_name,"target":other.1}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Member removed"})).into_response()
}
async fn rename_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() != Some("group") {
        return error("Only possible in groups", StatusCode::BAD_REQUEST);
    }
    if chat.try_get::<String, _>("role").ok().as_deref() != Some("owner") {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.chars().count() <= 64);
    let Some(name) = name else {
        return error(
            "Group name must be 1-64 characters",
            StatusCode::BAD_REQUEST,
        );
    };
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("UPDATE chats SET name=? WHERE id=?")
        .bind(name)
        .bind(&chat_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "renamed",
            json!({"actor":me.display_name,"name":name}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"Group renamed"})).into_response()
}
async fn delete_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    delete_chat_for(&state, &me, &chat_id).await
}
async fn delete_chat_for(state: &AppState, me: &User, chat_id: &str) -> axum::response::Response {
    let chat = match membership(&state.db, chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("group") {
        if sqlx::query("DELETE FROM chat_members WHERE chat_id=? AND user_id=?")
            .bind(chat_id)
            .bind(&me.id)
            .execute(&mut *tx)
            .await
            .is_err()
        {
            return db_error();
        }
        let remaining=sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=? ORDER BY joined_at, user_id COLLATE NOCASE").bind(chat_id).fetch_all(&mut *tx).await;
        let remaining = match remaining {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
        if remaining.is_empty() {
            if sqlx::query("DELETE FROM group_avatars WHERE chat_id=?")
                .bind(chat_id)
                .execute(&mut *tx)
                .await
                .is_err()
                || sqlx::query(
                    "DELETE FROM file_blobs WHERE id IN (SELECT id FROM files WHERE chat_id=?)",
                )
                .bind(chat_id)
                .execute(&mut *tx)
                .await
                .is_err()
                || sqlx::query("DELETE FROM files WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM pinned_messages WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM messages WHERE chat_id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                || sqlx::query("DELETE FROM chats WHERE id=?")
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
            {
                return db_error();
            }
        } else {
            if chat
                .try_get::<Option<String>, _>("owner_id")
                .ok()
                .flatten()
                .as_deref()
                == Some(&me.id)
            {
                let new_owner: String = remaining[0].try_get("user_id").unwrap_or_default();
                if sqlx::query("UPDATE chats SET owner_id=? WHERE id=?")
                    .bind(&new_owner)
                    .bind(chat_id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                    || sqlx::query(
                        "UPDATE chat_members SET role='owner' WHERE chat_id=? AND user_id=?",
                    )
                    .bind(chat_id)
                    .bind(new_owner)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                {
                    return db_error();
                }
            }
            if system_message(&mut tx, chat_id, "left", json!({"actor":me.display_name}))
                .await
                .is_err()
            {
                return db_error();
            }
        }
    } else {
        let max = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?",
        )
        .bind(chat_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        if sqlx::query(
            "UPDATE chat_members SET hidden=1,cleared_seq=? WHERE chat_id=? AND user_id=?",
        )
        .bind(max)
        .bind(chat_id)
        .bind(&me.id)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return db_error();
        }
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({"message":"Chat deleted successfully"})).into_response()
}
async fn target_member(pool: &SqlitePool, body: &Value) -> ApiResult<(String, String)> {
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| ApiError::new("Missing or invalid 'username'", StatusCode::BAD_REQUEST))?;
    let row=sqlx::query("SELECT id,COALESCE(NULLIF(display_name,''),username) AS display_name FROM users WHERE username=? COLLATE NOCASE").bind(name.trim()).fetch_optional(pool).await.map_err(|_|ApiError::new("Database unavailable",StatusCode::INTERNAL_SERVER_ERROR))?.ok_or_else(||ApiError::new("User not found",StatusCode::NOT_FOUND))?;
    Ok((
        row.try_get("id").unwrap_or_default(),
        row.try_get("display_name").unwrap_or_default(),
    ))
}

async fn single_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let row=sqlx::query("SELECT m.*,u.username sender,u.display_name sender_display FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.id=? AND m.chat_id=? AND m.seq>?").bind(&message_id).bind(&chat_id).bind(floor).fetch_optional(&state.db).await;
    let row = match row {
        Ok(Some(v)) => v,
        Ok(None) => return error("Message not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let msgs = match add_shares(&state.db, vec![serialize_message(&row)], &me.id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    json_ok(json!({"message":msgs[0]})).into_response()
}

async fn message_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let message=match sqlx::query("SELECT seq,created_at,sender_id FROM messages WHERE id=? AND chat_id=? AND deleted=0 AND seq>?").bind(&message_id).bind(&chat_id).bind(floor).fetch_optional(&state.db).await{Ok(Some(v))=>v,Ok(None)=>return error("Message not found",StatusCode::NOT_FOUND),Err(_)=>return db_error()};
    let seq = number(&message, "seq");
    let sender: Option<String> = message.try_get("sender_id").ok().flatten();
    let rows=match sqlx::query("SELECT u.id,u.username,u.display_name,m.delivered_seq,m.last_read_seq,m.joined_seq FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=?").bind(&chat_id).fetch_all(&state.db).await{Ok(v)=>v,Err(_)=>return db_error()};
    let mut members = Vec::new();
    for row in rows {
        let id: String = row.try_get("id").unwrap_or_default();
        if Some(id.as_str()) == sender.as_deref() || number(&row, "joined_seq") >= seq {
            continue;
        }
        let read = number(&row, "last_read_seq") >= seq;
        let delivered = read || number(&row, "delivered_seq") >= seq;
        let delivered_at = if delivered {
            receipt_time(&state.db, &chat_id, &id, "delivered", seq)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let read_at = if read {
            receipt_time(&state.db, &chat_id, &id, "read", seq)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        members.push(json!({"id":id,"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(&row),"delivered":delivered,"delivered_at":delivered_at,"read":read,"read_at":read_at}))
    }
    json_ok(json!({"sent_at":message.try_get::<String,_>("created_at").unwrap_or_default(),"members":members})).into_response()
}
async fn receipt_time(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
    kind: &str,
    seq: i64,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT MIN(at) FROM receipts WHERE chat_id=? AND user_id=? AND kind=? AND seq>=?",
    )
    .bind(chat)
    .bind(user)
    .bind(kind)
    .bind(seq)
    .fetch_one(pool)
    .await
}

async fn pin_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let message_id = body
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64);
    let Some(message_id) = message_id else {
        return error("Missing or invalid 'message_id'", StatusCode::BAD_REQUEST);
    };
    let pinned = body.get("pinned").and_then(Value::as_bool) != Some(false);
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let valid=sqlx::query("SELECT 1 FROM messages WHERE id=? AND chat_id=? AND deleted=0 AND silent=0 AND kind!='system' AND seq>?").bind(message_id).bind(&chat_id).bind(floor).fetch_optional(&state.db).await;
    match valid {
        Ok(Some(_)) => {}
        Ok(None) => return error("Message not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if pinned {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pinned_messages WHERE chat_id=?")
                .bind(&chat_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(0);
        if count >= 50 {
            return error("At most 50 pinned messages", StatusCode::BAD_REQUEST);
        }
        let added=sqlx::query("INSERT OR IGNORE INTO pinned_messages(chat_id,message_id,pinned_by,pinned_at) VALUES(?,?,?,?)").bind(&chat_id).bind(message_id).bind(&me.id).bind(now()).execute(&mut *tx).await.map(|r|r.rows_affected()).unwrap_or(0);
        if added > 0
            && system_message(
                &mut tx,
                &chat_id,
                "pinned",
                json!({"actor":me.display_name}),
            )
            .await
            .is_err()
        {
            return db_error();
        }
    } else if sqlx::query("DELETE FROM pinned_messages WHERE chat_id=? AND message_id=?")
        .bind(&chat_id)
        .bind(message_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return db_error();
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    match chat_pins(&state.db, &chat_id, floor).await {
        Ok(v) => json_ok(json!({"pins":v})).into_response(),
        Err(_) => db_error(),
    }
}
async fn chat_prefs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    for key in ["pinned", "archived"] {
        if let Some(v) = body.get(key) {
            let Some(value) = v.as_bool() else {
                return error(format!("Invalid '{key}'"), StatusCode::BAD_REQUEST);
            };
            let sql = format!("UPDATE chat_members SET {key}=? WHERE chat_id=? AND user_id=?");
            if sqlx::query(&sql)
                .bind(i64::from(value))
                .bind(&chat_id)
                .bind(&me.id)
                .execute(&mut *tx)
                .await
                .is_err()
            {
                return db_error();
            }
        }
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({})).into_response()
}
async fn set_disappearing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("group")
        && chat.try_get::<String, _>("role").ok().as_deref() != Some("owner")
    {
        return error("Only the group owner can do that", StatusCode::FORBIDDEN);
    }
    let Some(seconds) = body.get("seconds").and_then(Value::as_i64) else {
        return error("Invalid timer", StatusCode::BAD_REQUEST);
    };
    if ![0, 3600, 86400, 604800, 7776000].contains(&seconds) {
        return error("Invalid timer", StatusCode::BAD_REQUEST);
    }
    if seconds == number(&chat, "disappear_seconds") {
        return json_ok(json!({"disappear_seconds":seconds})).into_response();
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("UPDATE chats SET disappear_seconds=? WHERE id=?")
        .bind(seconds)
        .bind(&chat_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || system_message(
            &mut tx,
            &chat_id,
            "disappearing",
            json!({"actor":me.display_name,"seconds":seconds}),
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"disappear_seconds":seconds})).into_response()
}

async fn scheduled_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    match sqlx::query("SELECT id,send_at,created_at FROM scheduled_messages WHERE chat_id=? AND sender_id=? ORDER BY send_at").bind(&chat_id).bind(&me.id).fetch_all(&state.db).await {
        Ok(rows) => json_ok(json!({"messages":rows.iter().map(|r| json!({"id":r.try_get::<String,_>("id").unwrap_or_default(),"send_at":r.try_get::<String,_>("send_at").unwrap_or_default(),"created_at":r.try_get::<String,_>("created_at").unwrap_or_default()})).collect::<Vec<_>>()})).into_response(),
        Err(_) => db_error()
    }
}

async fn schedule_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let Some(id) = body
        .get("id")
        .and_then(Value::as_str)
        .filter(|v| v.len() <= 64)
    else {
        return error(
            "Invalid scheduled time or message id",
            StatusCode::BAD_REQUEST,
        );
    };
    let Some(at) = body.get("send_at").and_then(Value::as_str) else {
        return error(
            "Invalid scheduled time or message id",
            StatusCode::BAD_REQUEST,
        );
    };
    if Uuid::parse_str(id).is_err() {
        return error(
            "Invalid scheduled time or message id",
            StatusCode::BAD_REQUEST,
        );
    }
    let send_at = match chrono::DateTime::parse_from_rfc3339(at) {
        Ok(v) => v.with_timezone(&chrono::Utc),
        Err(_) => {
            return error(
                "Invalid scheduled time or message id",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let now_utc = chrono::Utc::now();
    if send_at < now_utc + chrono::Duration::minutes(1)
        || send_at > now_utc + chrono::Duration::days(365)
    {
        return error(
            "Schedule between one minute and one year from now",
            StatusCode::BAD_REQUEST,
        );
    }
    let members = match member_ids(&state.db, &chat_id).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm") {
        for member in &members {
            if member != &me.id && is_blocked(&state.db, &me.id, member).await.unwrap_or(true) {
                return error(
                    "You can't send messages to this chat",
                    StatusCode::FORBIDDEN,
                );
            }
        }
    }
    let Some(payload) = body.get("payload") else {
        return error("Unsupported message format", StatusCode::BAD_REQUEST);
    };
    if let Some(problem) = validate_envelope(payload, &members) {
        let status = if problem.contains("members") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        return error(problem, status);
    }
    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scheduled_messages WHERE sender_id=?")
            .bind(&me.id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
    if count >= 100 {
        return error("Too many scheduled messages", StatusCode::BAD_REQUEST);
    }
    match sqlx::query(
        "SELECT 1 FROM messages WHERE id=? UNION SELECT 1 FROM scheduled_messages WHERE id=?",
    )
    .bind(id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(_)) => return error("Duplicate message id", StatusCode::CONFLICT),
        Err(_) => return db_error(),
        Ok(None) => {}
    }
    let member_ids = match serde_json::to_string(&members) {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    match sqlx::query("INSERT INTO scheduled_messages(id,chat_id,sender_id,payload,member_ids,sender_sign_key,send_at,created_at) VALUES(?,?,?,?,?,?,?,?)")
        .bind(id).bind(&chat_id).bind(&me.id).bind(payload.to_string()).bind(member_ids).bind(me.pub_sign.unwrap_or_default())
        .bind(send_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()).bind(now()).execute(&state.db).await {
        Ok(_) => json_ok(json!({"message":"Message scheduled","id":id})).into_response(),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => error("Duplicate message id", StatusCode::CONFLICT),
        Err(_) => db_error()
    }
}

async fn cancel_scheduled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, message_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    match sqlx::query("DELETE FROM scheduled_messages WHERE id=? AND chat_id=? AND sender_id=?")
        .bind(message_id)
        .bind(chat_id)
        .bind(me.id)
        .execute(&state.db)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            json_ok(json!({"message":"Scheduled message cancelled"})).into_response()
        }
        Ok(_) => error("Scheduled message not found", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}

async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    body: Bytes,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if membership(&state.db, &chat_id, &me.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return error("Chat not found", StatusCode::NOT_FOUND);
    }
    if state.rate_limited(format!("upload:{}", me.id), 30, 60) {
        return error("You are uploading too fast", StatusCode::TOO_MANY_REQUESTS);
    }
    if body.is_empty() {
        return error("Empty file", StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_FILE_BYTES {
        return error("Files can be at most 16 MB", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let pending = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM files WHERE uploader_id=? AND message_id IS NULL",
    )
    .bind(&me.id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    if pending >= 30 {
        return error(
            "Too many unsent attachments, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let id = Uuid::new_v4().simple().to_string();
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("INSERT INTO file_blobs(id,data) VALUES(?,?)").bind(&id).bind(body.as_ref()).execute(&mut *tx).await.is_err()||sqlx::query("INSERT INTO files(id,chat_id,uploader_id,message_id,size,created_at) VALUES(?,?,?,NULL,?,?)").bind(&id).bind(&chat_id).bind(&me.id).bind(body.len() as i64).bind(now()).execute(&mut *tx).await.is_err()||tx.commit().await.is_err(){return db_error()}
    json_ok(json!({"file_id":id})).into_response()
}
async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, file_id)): Path<(String, String)>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let floor = number(&chat, "joined_seq").max(number(&chat, "cleared_seq"));
    let row=sqlx::query("SELECT f.uploader_id,f.message_id,m.seq,b.data FROM files f LEFT JOIN messages m ON m.id=f.message_id LEFT JOIN file_blobs b ON b.id=f.id WHERE f.id=? AND f.chat_id=?").bind(file_id).bind(&chat_id).fetch_optional(&state.db).await;
    let row = match row {
        Ok(Some(v)) => v,
        Ok(None) => return error("File not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let message_id: Option<String> = row.try_get("message_id").ok().flatten();
    let visible = if message_id.is_none() {
        row.try_get::<String, _>("uploader_id").ok().as_deref() == Some(me.id.as_str())
    } else {
        row.try_get::<Option<i64>, _>("seq")
            .ok()
            .flatten()
            .is_some_and(|seq| seq > floor)
    };
    if !visible {
        return error("File not found", StatusCode::NOT_FOUND);
    }
    let Some(data) = row.try_get::<Option<Vec<u8>>, _>("data").ok().flatten() else {
        return error("File not found", StatusCode::NOT_FOUND);
    };
    let mut response = axum::body::Body::from(data).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, max-age=604800, immutable"),
    );
    response
}

async fn share_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((chat_id, target_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    if target_id == me.id {
        return error(
            "You can't share the history with yourself",
            StatusCode::BAD_REQUEST,
        );
    }
    let target = match membership(&state.db, &chat_id, &target_id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let reset = number(&target, "reset_seq");
    if reset == 0 {
        return error("There is nothing to share", StatusCode::CONFLICT);
    }
    let empty = serde_json::Map::new();
    let keys = match body.get("keys") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => &empty,
        Some(Value::Number(value)) if value.as_i64() == Some(0) => &empty,
        Some(Value::String(value)) if value.is_empty() => &empty,
        Some(Value::Array(value)) if value.is_empty() => &empty,
        Some(Value::Object(value)) => value,
        Some(_) => return error("Invalid keys", StatusCode::BAD_REQUEST),
    };
    if keys.len() > 500 {
        return error("Invalid keys", StatusCode::BAD_REQUEST);
    }
    for (id, wrapped) in keys {
        if id.len() > 64
            || !wrapped.is_object()
            || !valid_b64_field(wrapped.get("iv"), 64)
            || !valid_b64_field(wrapped.get("k"), 128)
        {
            return error("Invalid keys", StatusCode::BAD_REQUEST);
        }
    }
    let lowest = number(&target, "joined_seq")
        .max(number(&target, "reset_cleared_seq"))
        .max(number(&chat, "joined_seq"))
        .max(number(&chat, "cleared_seq"));
    let my_pub = me.id.as_str();
    let pub_ecdh =
        match sqlx::query_scalar::<_, Option<String>>("SELECT pub_ecdh FROM users WHERE id=?")
            .bind(my_pub)
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(v)) => v.unwrap_or_default(),
            _ => return db_error(),
        };
    let mut stored = 0i64;
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    for (id, wrapped) in keys {
        let eligible=sqlx::query("SELECT 1 FROM messages WHERE chat_id=? AND id=? AND kind='e2e' AND deleted=0 AND seq>? AND seq<=?").bind(&chat_id).bind(id).bind(lowest).bind(reset).fetch_optional(&mut *tx).await;
        match eligible {
            Ok(Some(_)) => {}
            Ok(None) => continue,
            Err(_) => return db_error(),
        }
        let iv = wrapped
            .get("iv")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let k = wrapped.get("k").and_then(Value::as_str).unwrap_or_default();
        match sqlx::query("INSERT OR IGNORE INTO message_key_shares(message_id,recipient_id,sharer_id,sharer_pub_ecdh,iv,k,created_at) VALUES(?,?,?,?,?,?,?)").bind(id).bind(&target_id).bind(&me.id).bind(&pub_ecdh).bind(iv).bind(k).bind(now()).execute(&mut *tx).await{Ok(v)=>stored+=v.rows_affected() as i64,Err(_)=>return db_error()}
    }
    if body.get("done").and_then(Value::as_bool) == Some(true) {
        let target_name = match sqlx::query(
            "SELECT COALESCE(NULLIF(display_name,''),username) AS name FROM users WHERE id=?",
        )
        .bind(&target_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(Some(row)) => row.try_get::<String, _>("name").unwrap_or_default(),
            _ => return db_error(),
        };
        if sqlx::query("UPDATE chat_members SET cleared_seq=MIN(cleared_seq,?),reset_seq=0,reset_cleared_seq=0 WHERE chat_id=? AND user_id=? AND cleared_seq<=reset_seq").bind(number(&target,"reset_cleared_seq")).bind(&chat_id).bind(&target_id).execute(&mut *tx).await.is_err()||sqlx::query("UPDATE chat_members SET reset_seq=0,reset_cleared_seq=0 WHERE chat_id=? AND user_id=?").bind(&chat_id).bind(&target_id).execute(&mut *tx).await.is_err()||system_message(&mut tx,&chat_id,"history_shared",json!({"actor":me.display_name,"target":target_name,"target_id":target_id})).await.is_err(){return db_error()}
    }
    if tx.commit().await.is_err() {
        return db_error();
    }
    json_ok(json!({"stored":stored})).into_response()
}

async fn previous_key_history(
    pool: &SqlitePool,
    ids: &[String],
) -> Result<HashMap<String, Vec<Value>>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let query = format!(
        "SELECT user_id,pub_ecdh,pub_sign,replaced_at FROM user_key_history WHERE user_id IN ({placeholders}) ORDER BY replaced_at"
    );
    let mut q = sqlx::query(&query);
    for id in ids {
        q = q.bind(id)
    }
    let rows = q.fetch_all(pool).await?;
    let mut result: HashMap<String, Vec<Value>> = HashMap::new();
    for row in rows {
        let id: String = row.try_get("user_id")?;
        result.entry(id).or_default().push(json!({"pub_ecdh":row.try_get::<String,_>("pub_ecdh")?,"pub_sign":row.try_get::<String,_>("pub_sign")?,"until":row.try_get::<String,_>("replaced_at")?}))
    }
    Ok(result)
}

async fn chat_pins(pool: &SqlitePool, chat: &str, floor: i64) -> Result<Vec<Value>, sqlx::Error> {
    let rows=sqlx::query("SELECT p.message_id,p.pinned_at,m.seq,u.username,u.display_name FROM pinned_messages p JOIN messages m ON m.id=p.message_id LEFT JOIN users u ON u.id=p.pinned_by WHERE p.chat_id=? AND m.deleted=0 AND m.seq>? ORDER BY p.pinned_at DESC").bind(chat).bind(floor).fetch_all(pool).await?;
    Ok(rows.iter().map(|r|json!({"message_id":r.try_get::<String,_>("message_id").unwrap_or_default(),"seq":number(r,"seq"),"pinned_at":r.try_get::<String,_>("pinned_at").unwrap_or_default(),"pinned_by":if r.try_get::<Option<String>,_>("username").ok().flatten().is_some(){Some(display_name(r))}else{None}})).collect())
}

async fn deliver_due_messages(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let due =
        sqlx::query("SELECT * FROM scheduled_messages WHERE send_at<=? ORDER BY send_at LIMIT 100")
            .bind(now())
            .fetch_all(pool)
            .await?;
    if due.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for item in due {
        let id: String = item.try_get("id")?;
        let chat_id: String = item.try_get("chat_id")?;
        let sender: String = item.try_get("sender_id")?;
        let payload: String = item.try_get("payload")?;
        let expected: String = item.try_get("member_ids")?;
        let sender_key: String = item.try_get("sender_sign_key")?;
        let chat = sqlx::query("SELECT type,disappear_seconds FROM chats WHERE id=?")
            .bind(&chat_id)
            .fetch_optional(&mut *tx)
            .await?;
        let sender_row = sqlx::query("SELECT pub_sign FROM users WHERE id=?")
            .bind(&sender)
            .fetch_optional(&mut *tx)
            .await?;
        let current =
            sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=? ORDER BY user_id")
                .bind(&chat_id)
                .fetch_all(&mut *tx)
                .await?;
        let members = current
            .iter()
            .map(|row| row.try_get::<String, _>("user_id"))
            .collect::<Result<Vec<_>, _>>()?;
        let members_now = serde_json::to_string(&members).unwrap_or_default();
        let keys_match = sender_row
            .and_then(|row| row.try_get::<Option<String>, _>("pub_sign").ok().flatten())
            .unwrap_or_default()
            == sender_key;
        let chat = chat;
        let mut can_send = chat.is_some() && keys_match && members_now == expected;
        if let Some(row) = &chat
            && row.try_get::<String, _>("type")?.as_str() == "dm"
        {
            for member in &members {
                if member != &sender && is_blocked(pool, &sender, member).await? {
                    can_send = false;
                    break;
                }
            }
        }
        if can_send {
            let rev = next_rev(&mut tx).await?;
            let disappear = chat
                .as_ref()
                .map(|r| r.try_get::<i64, _>("disappear_seconds").unwrap_or(0))
                .unwrap_or(0);
            let created = now();
            let expires = if disappear > 0 {
                Some(
                    (chrono::Utc::now() + chrono::Duration::seconds(disappear))
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string(),
                )
            } else {
                None
            };
            let result=sqlx::query("INSERT OR IGNORE INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev,expires_at) VALUES(?,?,?,'e2e',?,?,?,?)").bind(&id).bind(&chat_id).bind(&sender).bind(payload).bind(&created).bind(rev).bind(expires).execute(&mut *tx).await?;
            if result.rows_affected() > 0 {
                let seq = result.last_insert_rowid();
                sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
                    .bind(&created)
                    .bind(&chat_id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE chat_members SET hidden=0 WHERE chat_id=?")
                    .bind(&chat_id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE chat_members SET last_read_seq=?,delivered_seq=? WHERE chat_id=? AND user_id=?").bind(seq).bind(seq).bind(&chat_id).bind(&sender).execute(&mut *tx).await?;
            }
        }
        sqlx::query("DELETE FROM scheduled_messages WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

struct User {
    id: String,
    display_name: String,
    pub_sign: Option<String>,
}
async fn user(state: &AppState, headers: &HeaderMap) -> ApiResult<User> {
    let row = require_user(state, headers).await?;
    Ok(User {
        id: row.try_get("id").unwrap_or_default(),
        display_name: display_name(&row),
        pub_sign: row.try_get("pub_sign").ok().flatten(),
    })
}
fn display_name(row: &SqliteRow) -> String {
    row.try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
        .or_else(|| row.try_get("username").ok())
        .unwrap_or_default()
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn db_error() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}
fn number(row: &SqliteRow, key: &str) -> i64 {
    row.try_get(key).unwrap_or(0)
}
fn history_reset(row: &SqliteRow) -> Value {
    let reset = number(row, "reset_seq");
    if reset == 0 {
        return Value::Null;
    }
    json!({"from_seq":number(row,"joined_seq").max(number(row,"reset_cleared_seq")),"until_seq":reset})
}
fn serialize_message(row: &SqliteRow) -> Value {
    let deleted = number(row, "deleted") != 0;
    let payload: Option<String> = row.try_get("payload").ok().flatten();
    let payload = if deleted {
        None
    } else {
        payload.and_then(|v| serde_json::from_str::<Value>(&v).ok())
    };
    json!({"seq":number(row,"seq"),"rev":number(row,"rev"),"id":row.try_get::<String,_>("id").unwrap_or_default(),"sender_id":row.try_get::<Option<String>,_>("sender_id").ok().flatten(),"sender":row.try_get::<Option<String>,_>("sender").ok().flatten(),"sender_display":row.try_get::<Option<String>,_>("sender_display").ok().flatten().filter(|v|!v.is_empty()).or_else(||row.try_get("sender").ok().flatten()),"kind":row.try_get::<String,_>("kind").unwrap_or_default(),"payload":payload,"created_at":row.try_get::<String,_>("created_at").unwrap_or_default(),"edited_at":row.try_get::<Option<String>,_>("edited_at").ok().flatten(),"deleted":deleted,"silent":number(row,"silent")!=0,"expires_at":row.try_get::<Option<String>,_>("expires_at").ok().flatten()})
}

async fn membership(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
) -> Result<Option<SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT c.*,m.role,m.joined_seq,m.cleared_seq,m.last_read_seq,m.hidden,m.pinned,m.archived,m.delivered_seq,m.reset_seq,m.reset_cleared_seq FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(chat).bind(user).fetch_optional(pool).await
}
async fn member_ids(pool: &SqlitePool, chat: &str) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=? ORDER BY user_id")
        .bind(chat)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| r.try_get("user_id").ok())
        .collect())
}
async fn insert_member(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    user: &str,
    role: &str,
) -> Result<(), sqlx::Error> {
    let seq =
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?")
            .bind(chat)
            .fetch_one(&mut **tx)
            .await?;
    sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,last_read_seq) VALUES(?,?,?,?,?,0,?)").bind(chat).bind(user).bind(role).bind(now()).bind(seq).bind(seq).execute(&mut **tx).await?;
    Ok(())
}
async fn max_seq(pool: &SqlitePool, chat: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?")
        .bind(chat)
        .fetch_one(pool)
        .await
}
async fn next_rev(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(rev),0)+1 FROM messages")
        .fetch_one(&mut **tx)
        .await
}
pub(crate) async fn system_message(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    event: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    let rev = next_rev(tx).await?;
    let created = now();
    let mut payload = details.as_object().cloned().unwrap_or_default();
    payload.insert("event".into(), json!(event));
    sqlx::query("INSERT INTO messages(id,chat_id,sender_id,kind,payload,created_at,rev) VALUES(?, ?, NULL,'system',?,?,?)").bind(Uuid::new_v4().to_string()).bind(chat).bind(Value::Object(payload).to_string()).bind(created.clone()).bind(rev).execute(&mut **tx).await?;
    sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
        .bind(created)
        .bind(chat)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn are_friends(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    let (x, y) = pair(a, b);
    Ok(
        sqlx::query("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?")
            .bind(x)
            .bind(y)
            .fetch_optional(pool)
            .await?
            .is_some(),
    )
}
async fn is_blocked(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)").bind(a).bind(b).bind(b).bind(a).fetch_optional(pool).await?.is_some())
}

fn validate_envelope(payload: &Value, members: &[String]) -> Option<String> {
    if payload
        .as_object()
        .is_none_or(|p| p.get("v").and_then(Value::as_i64) != Some(1))
    {
        return Some("Unsupported message format".into());
    }
    for (field, max) in [("iv", 64usize), ("sig", 256), ("ct", MAX_CIPHERTEXT_LEN)] {
        if !valid_b64_field(payload.get(field), max) {
            return Some(format!("Invalid '{field}'"));
        }
    }
    let Some(keys) = payload.get("keys").and_then(Value::as_object) else {
        return Some("Message must be encrypted for exactly the current chat members".into());
    };
    let mut actual = keys.keys().cloned().collect::<Vec<_>>();
    actual.sort();
    let mut expected = members.to_vec();
    expected.sort();
    if actual != expected {
        return Some("Message must be encrypted for exactly the current chat members".into());
    }
    for wrapped in keys.values() {
        let Some(wrapped) = wrapped.as_object() else {
            return Some("Invalid key".into());
        };
        for field in ["iv", "k"] {
            if !valid_b64_field(wrapped.get(field), 128) {
                return Some("Invalid key".into());
            }
        }
    }
    if payload.as_object().is_some_and(|p| {
        p.keys()
            .any(|k| !matches!(k.as_str(), "v" | "iv" | "ct" | "sig" | "keys"))
    }) {
        return Some("Unknown fields in message".into());
    }
    None
}
fn valid_b64_field(value: Option<&Value>, max: usize) -> bool {
    value.and_then(Value::as_str).is_some_and(|v| {
        let unpadded = v.trim_end_matches('=');
        let padding = v.len() - unpadded.len();
        !v.is_empty()
            && v.len() <= max
            && padding <= 2
            && unpadded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b))
    })
}

async fn advance_receipt(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
    kind: &str,
    seq: i64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let kinds: &[&str] = if kind == "read" {
        &["delivered", "read"]
    } else {
        &["delivered"]
    };
    for k in kinds {
        let column = if *k == "read" {
            "last_read_seq"
        } else {
            "delivered_seq"
        };
        let q = format!(
            "UPDATE chat_members SET {column}=? WHERE chat_id=? AND user_id=? AND {column}<?"
        );
        let r = sqlx::query(&q)
            .bind(seq)
            .bind(chat)
            .bind(user)
            .bind(seq)
            .execute(&mut *tx)
            .await?;
        if r.rows_affected() > 0 {
            sqlx::query("INSERT INTO receipts(chat_id,user_id,kind,seq,at) VALUES(?,?,?,?,?)")
                .bind(chat)
                .bind(user)
                .bind(k)
                .bind(seq)
                .bind(now())
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await
}
async fn member_receipts(
    pool: &SqlitePool,
    chat: &str,
    me: &str,
) -> Result<Option<Value>, sqlx::Error> {
    let row=sqlx::query("SELECT MIN(delivered_seq) delivered,MIN(last_read_seq) read,COUNT(*) n FROM chat_members WHERE chat_id=? AND user_id!=?").bind(chat).bind(me).fetch_one(pool).await?;
    if number(&row, "n") == 0 {
        return Ok(None);
    }
    let read = number(&row, "read");
    Ok(Some(
        json!({"delivered_seq":number(&row,"delivered").max(read),"read_seq":read}),
    ))
}
async fn add_shares(
    pool: &SqlitePool,
    mut messages: Vec<Value>,
    user: &str,
) -> Result<Vec<Value>, sqlx::Error> {
    for message in &mut messages {
        let Some(id) = message.get("id").and_then(Value::as_str) else {
            continue;
        };
        if let Some(row)=sqlx::query("SELECT iv,k,sharer_pub_ecdh FROM message_key_shares WHERE recipient_id=? AND message_id=?").bind(user).bind(id).fetch_optional(pool).await?{message["share"]=json!({"iv":row.try_get::<String,_>("iv")?,"k":row.try_get::<String,_>("k")?,"from_pub":row.try_get::<String,_>("sharer_pub_ecdh")?})}
    }
    Ok(messages)
}
async fn typing_values(state: &AppState, chat: &str, me: &str) -> Vec<Value> {
    let ids = state.typing_users(chat, me);
    if ids.is_empty() {
        return vec![];
    }
    let mut result = Vec::new();
    for id in ids {
        if let Ok(Some(row)) = sqlx::query("SELECT id,username,display_name FROM users WHERE id=?")
            .bind(id)
            .fetch_optional(&state.db)
            .await
        {
            result.push(json!({"id":row.try_get::<String,_>("id").unwrap_or_default(),"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(&row)}))
        }
    }
    result
}
async fn purge_expired(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let timestamp = now();
    let expired=sqlx::query("SELECT id,chat_id FROM messages WHERE expires_at IS NOT NULL AND expires_at<=? AND deleted=0").bind(&timestamp).fetch_all(pool).await?;
    let stale_cutoff = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let stale = sqlx::query("SELECT id FROM files WHERE message_id IS NULL AND created_at<=?")
        .bind(stale_cutoff)
        .fetch_all(pool)
        .await?;
    if expired.is_empty() && stale.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for row in expired {
        let id: String = row.try_get("id")?;
        let chat: String = row.try_get("chat_id")?;
        let rev = next_rev(&mut tx).await?;
        sqlx::query("UPDATE messages SET deleted=1,payload=NULL,rev=? WHERE id=?")
            .bind(rev)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        forget_message_data(&mut tx, &chat, &id).await?
    }
    for row in stale {
        let id: String = row.try_get("id")?;
        sqlx::query("DELETE FROM file_blobs WHERE id=?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM files WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}
async fn forget_message_data(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    let files = sqlx::query("SELECT id FROM files WHERE message_id=?")
        .bind(message)
        .fetch_all(&mut **tx)
        .await?;
    for f in files {
        let id: String = f.try_get("id")?;
        sqlx::query("DELETE FROM file_blobs WHERE id=?")
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("DELETE FROM files WHERE message_id=?")
        .bind(message)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM pinned_messages WHERE chat_id=? AND message_id=?")
        .bind(chat)
        .bind(message)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM message_key_shares WHERE message_id=?")
        .bind(message)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn chat_summary(state: &AppState, row: &SqliteRow, me: &str) -> Result<Value, sqlx::Error> {
    let id: String = row.try_get("id")?;
    let floor = number(row, "joined_seq").max(number(row, "cleared_seq"));
    let last=sqlx::query("SELECT m.*,u.username sender,u.display_name sender_display FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? AND m.seq>? AND m.deleted=0 AND m.silent=0 ORDER BY m.seq DESC LIMIT 1").bind(&id).bind(floor).fetch_optional(&state.db).await?;
    let unread=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM messages WHERE chat_id=? AND seq>? AND deleted=0 AND silent=0 AND kind!='system' AND (sender_id IS NULL OR sender_id!=?)").bind(&id).bind(floor.max(number(row,"last_read_seq"))).bind(me).fetch_one(&state.db).await?;
    let members=sqlx::query("SELECT u.id,u.username,u.display_name FROM chat_members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? ORDER BY m.joined_at,u.username COLLATE NOCASE").bind(&id).fetch_all(&state.db).await?;
    let ty: String = row.try_get("type")?;
    let mut value = json!({"id":id,"chat":id,"type":ty,"name":row.try_get::<Option<String>,_>("name")?,"avatar_updated_at":row.try_get::<Option<String>,_>("avatar_updated_at").ok().flatten(),"role":row.try_get::<String,_>("role")?,"member_count":members.len(),"last_message":last.as_ref().map(serialize_message),"unread":unread,"last_activity":row.try_get::<String,_>("last_activity")?,"pinned":number(row,"pinned")!=0,"archived":number(row,"archived")!=0,"disappear_seconds":number(row,"disappear_seconds"),"typing":typing_values(state,&id,me).await});
    if ty == "dm" {
        let other = members
            .iter()
            .find(|m| m.try_get::<String, _>("id").ok().as_deref() != Some(me));
        let other_id = other.and_then(|r| r.try_get::<String, _>("id").ok());
        let other_name = other
            .map(display_name)
            .unwrap_or_else(|| "Unknown User".into());
        let blocked = if let Some(oid) = &other_id {
            is_blocked(&state.db, me, oid).await.unwrap_or(false)
        } else {
            false
        };
        let muted = if let Some(oid) = &other_id {
            sqlx::query("SELECT 1 FROM muted_users WHERE user_id=? AND muted_id=?")
                .bind(me)
                .bind(oid)
                .fetch_optional(&state.db)
                .await?
                .is_some()
        } else {
            false
        };
        let presence = if let Some(oid) = &other_id {
            presence(&state.db, me, oid).await?
        } else {
            None
        };
        value["other_user"] = other
            .and_then(|r| r.try_get::<String, _>("username").ok())
            .map(Value::String)
            .unwrap_or(json!("Unknown User"));
        value["other_user_id"] = other_id.map(Value::String).unwrap_or(Value::Null);
        value["name"] = json!(other_name);
        value["blocked"] = json!(blocked);
        value["muted"] = json!(muted);
        value["presence"] = presence.unwrap_or(Value::Null)
    }
    Ok(value)
}
async fn presence(pool: &SqlitePool, me: &str, other: &str) -> Result<Option<Value>, sqlx::Error> {
    let visible=are_friends(pool,me,other).await?||sqlx::query("SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id=b.chat_id WHERE a.user_id=? AND b.user_id=?").bind(me).bind(other).fetch_optional(pool).await?.is_some();
    if !visible {
        return Ok(None);
    }
    let row=sqlx::query("SELECT a.show_last_seen av,b.show_last_seen bv,b.last_seen FROM users a JOIN users b ON b.id=? WHERE a.id=?").bind(other).bind(me).fetch_optional(pool).await?;
    let Some(row) = row else { return Ok(None) };
    if number(&row, "av") == 0 || number(&row, "bv") == 0 {
        return Ok(None);
    }
    let Some(last) = row.try_get::<Option<String>, _>("last_seen")? else {
        return Ok(None);
    };
    let time = chrono::DateTime::parse_from_str(
        &format!("{}+00:00", last.trim_end_matches('Z')),
        "%Y-%m-%dT%H:%M:%S%:z",
    )
    .ok();
    let online = time
        .is_some_and(|v| (chrono::Utc::now() - v.with_timezone(&chrono::Utc)).num_seconds() < 45);
    Ok(Some(json!({"online":online,"last_seen":last})))
}
