use super::{ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::collections::HashMap;
use uuid::Uuid;

const RING_SECONDS: i64 = 45;
const GONE_SECONDS: i64 = 20;
const MAX_GROUP_MEMBERS: usize = 50;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/chats/{chat_id}/call", post(call_chat))
        .route("/api/calls/{call_id}/answer", post(answer_call))
        .route("/api/calls/{call_id}/decline", post(decline_call))
        .route("/api/calls/{call_id}/leave", post(leave_call))
        .route("/api/calls", get(my_calls))
        .route("/api/calls/{call_id}/signal", post(call_signal))
        .route("/api/calls/{call_id}/add", post(add_to_call))
        .route("/api/calls/ice", get(ice_servers))
}

struct Caller {
    id: String,
    display_name: String,
}
async fn caller(state: &AppState, headers: &HeaderMap) -> ApiResult<Caller> {
    let row = require_user(state, headers).await?;
    Ok(Caller {
        id: row.try_get("id").unwrap_or_default(),
        display_name: row
            .try_get::<Option<String>, _>("display_name")
            .ok()
            .flatten()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| row.try_get("username").unwrap_or_default()),
    })
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn ago(seconds: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
fn err_db() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}

async fn call_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let chat = match membership(&state.db, &chat_id, &me.id).await {
        Ok(Some(v)) => v,
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return err_db(),
    };
    if chat.try_get::<String, _>("type").ok().as_deref() == Some("dm") {
        let members = match member_ids(&state.db, &chat_id).await {
            Ok(v) => v,
            Err(_) => return err_db(),
        };
        let Some(other) = members.iter().find(|v| *v != &me.id) else {
            return error("You can't call this person", StatusCode::FORBIDDEN);
        };
        if blocked(&state.db, &me.id, other).await.unwrap_or(true) {
            return error("You can't call this person", StatusCode::FORBIDDEN);
        }
    }
    if state.rate_limited(format!("call:{}", me.id), 20, 600) {
        return error(
            "Too many calls, please wait a moment",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if expire_calls(&mut tx).await.is_err() {
        return err_db();
    };
    let active=sqlx::query("SELECT id FROM calls WHERE chat_id=? AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1").bind(&chat_id).fetch_optional(&mut *tx).await;
    let call_id = match active {
        Ok(Some(row)) => {
            let id: String = row.try_get("id").unwrap_or_default();
            if leave_other_calls(&mut tx, &me.id, Some(&id)).await.is_err()
                || set_state(&mut tx, &id, &me.id, "joined").await.is_err()
                || sqlx::query("UPDATE calls SET answered_at=COALESCE(answered_at,?) WHERE id=?")
                    .bind(now())
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .is_err()
            {
                return err_db();
            }
            id
        }
        Ok(None) => match start_call(&mut tx, &chat_id, &me.id).await {
            Ok(v) => v,
            Err(_) => return err_db(),
        },
        Err(_) => return err_db(),
    };
    if tx.commit().await.is_err() {
        return err_db();
    };
    match serialize_call(&state.db, &call_id, &me.id).await {
        Ok(v) => json_ok(json!({"call":v})).into_response(),
        Err(_) => err_db(),
    }
}

async fn answer_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["ringing", "joined"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if leave_other_calls(&mut tx, &me.id, Some(&call_id))
        .await
        .is_err()
        || set_state(&mut tx, &call_id, &me.id, "joined")
            .await
            .is_err()
        || sqlx::query("UPDATE calls SET answered_at=COALESCE(answered_at,?) WHERE id=?")
            .bind(now())
            .bind(&call_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return err_db();
    }
    match serialize_call(&state.db, &call_id, &me.id).await {
        Ok(v) => json_ok(json!({"call":v})).into_response(),
        Err(_) => err_db(),
    }
}
async fn decline_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["ringing"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if set_state(&mut tx, &call_id, &me.id, "declined")
        .await
        .is_err()
        || finish_if_over(&mut tx, &call_id).await.is_err()
        || tx.commit().await.is_err()
    {
        return err_db();
    }
    json_ok(json!({})).into_response()
}
async fn leave_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["ringing", "joined"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if set_state(&mut tx, &call_id, &me.id, "left").await.is_err()
        || finish_if_over(&mut tx, &call_id).await.is_err()
        || tx.commit().await.is_err()
    {
        return err_db();
    }
    json_ok(json!({})).into_response()
}

async fn my_calls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let after = query
        .get("after")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if expire_calls(&mut tx).await.is_err()||sqlx::query("UPDATE call_participants SET seen_at=? WHERE user_id=? AND state='joined' AND call_id IN (SELECT id FROM calls WHERE ended_at IS NULL)").bind(now()).bind(&me.id).execute(&mut *tx).await.is_err()||tx.commit().await.is_err(){return err_db()};
    let rows=sqlx::query("SELECT c.id FROM calls c JOIN call_participants p ON p.call_id=c.id WHERE p.user_id=? AND p.state IN ('ringing','joined') AND c.ended_at IS NULL ORDER BY c.started_at").bind(&me.id).fetch_all(&state.db).await;
    let rows = match rows {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    let mut calls = Vec::new();
    for row in rows {
        let id: String = row.try_get("id").unwrap_or_default();
        match serialize_call(&state.db, &id, &me.id).await {
            Ok(v) => calls.push(v),
            Err(_) => return err_db(),
        }
    }
    let signals = sqlx::query(
        "SELECT id,call_id,from_id,kind,data FROM call_signals WHERE to_id=? AND id>? ORDER BY id",
    )
    .bind(&me.id)
    .bind(after)
    .fetch_all(&state.db)
    .await;
    let signals = match signals {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    let signals=signals.iter().map(|r|{let data=r.try_get::<String,_>("data").ok().and_then(|v|serde_json::from_str::<Value>(&v).ok()).unwrap_or(Value::Null);json!({"id":r.try_get::<i64,_>("id").unwrap_or(0),"call_id":r.try_get::<String,_>("call_id").unwrap_or_default(),"from":r.try_get::<String,_>("from_id").unwrap_or_default(),"kind":r.try_get::<String,_>("kind").unwrap_or_default(),"data":data})}).collect::<Vec<_>>();
    json_ok(json!({"calls":calls,"signals":signals})).into_response()
}

async fn call_signal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if require_call(&state.db, &call_id, &me.id, &["joined"])
        .await
        .is_err()
    {
        return error("This call has ended", StatusCode::NOT_FOUND);
    }
    let Some(to) = body
        .get("to")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 64)
    else {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    };
    let Some(kind @ ("offer" | "answer")) = body.get("kind").and_then(Value::as_str) else {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    };
    let data = body.get("data");
    let Some(data) = data.and_then(Value::as_object) else {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    };
    let sdp = data.get("sdp").and_then(Value::as_str);
    let sig = data.get("sig").and_then(Value::as_str);
    if data.keys().any(|k| k != "sdp" && k != "sig")
        || sdp.is_none_or(|v| v.is_empty() || v.len() > 16000)
        || sig.is_none_or(|v| !valid_b64(v, 256))
    {
        return error("Invalid signal", StatusCode::BAD_REQUEST);
    }
    if state.rate_limited(format!("call-signal:{}", me.id), 120, 60) {
        return error("Too many signals", StatusCode::TOO_MANY_REQUESTS);
    }
    let target = sqlx::query("SELECT state FROM call_participants WHERE call_id=? AND user_id=?")
        .bind(&call_id)
        .bind(to)
        .fetch_optional(&state.db)
        .await;
    match target {
        Ok(Some(row)) if row.try_get::<String, _>("state").ok().as_deref() == Some("joined") => {}
        _ => return error("This person is not in the call", StatusCode::CONFLICT),
    }
    match sqlx::query(
        "INSERT INTO call_signals(call_id,from_id,to_id,kind,data,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(&call_id)
    .bind(&me.id)
    .bind(to)
    .bind(kind)
    .bind(Value::Object(data.clone()).to_string())
    .bind(now())
    .execute(&state.db)
    .await
    {
        Ok(_) => json_ok(json!({})).into_response(),
        Err(_) => err_db(),
    }
}

async fn add_to_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match caller(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let call = match require_call(&state.db, &call_id, &me.id, &["joined"]).await {
        Ok(v) => v,
        Err(_) => return error("This call has ended", StatusCode::NOT_FOUND),
    };
    let Some(usernames) = body
        .get("usernames")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= MAX_GROUP_MEMBERS)
    else {
        return error("Pick at least one friend", StatusCode::BAD_REQUEST);
    };
    let joined = sqlx::query(
        "SELECT user_id FROM call_participants WHERE call_id=? AND state='joined' AND user_id!=?",
    )
    .bind(&call_id)
    .bind(&me.id)
    .fetch_all(&state.db)
    .await;
    let joined = match joined {
        Ok(v) => v
            .iter()
            .filter_map(|r| r.try_get::<String, _>("user_id").ok())
            .collect::<Vec<_>>(),
        Err(_) => return err_db(),
    };
    let mut added = Vec::new();
    for name in usernames {
        let text = name.as_str().unwrap_or("");
        let row=sqlx::query("SELECT id,COALESCE(NULLIF(display_name,''),username) AS name FROM users WHERE username=? COLLATE NOCASE").bind(text.trim()).fetch_optional(&state.db).await;
        let (id, _) = match row {
            Ok(Some(r)) => (
                r.try_get::<String, _>("id").unwrap_or_default(),
                r.try_get::<String, _>("name").unwrap_or_default(),
            ),
            _ => {
                return error(
                    format!("{text} is not your friend"),
                    StatusCode::BAD_REQUEST,
                );
            }
        };
        if !are_friends(&state.db, &me.id, &id).await.unwrap_or(false) {
            return error(
                format!("{text} is not your friend"),
                StatusCode::BAD_REQUEST,
            );
        }
        if id != me.id && !joined.contains(&id) && !added.iter().any(|v| v == &id) {
            added.push(id)
        }
    }
    if added.is_empty() {
        return error(
            "These people are already in the call",
            StatusCode::BAD_REQUEST,
        );
    }
    let mut member_ids = joined.clone();
    member_ids.extend(added);
    if member_ids.len() + 1 > MAX_GROUP_MEMBERS {
        return error(
            format!("A group can have at most {MAX_GROUP_MEMBERS} members"),
            StatusCode::BAD_REQUEST,
        );
    }
    let mut names = vec![me.display_name.clone()];
    for id in &member_ids {
        let name = sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(NULLIF(display_name,''),username) FROM users WHERE id=?",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await;
        match name {
            Ok(Some(v)) => names.push(v),
            _ => return err_db(),
        }
    }
    let mut group_name = names.join(", ");
    if group_name.chars().count() > 64 {
        group_name = group_name
            .chars()
            .take(61)
            .collect::<String>()
            .trim_end_matches(", ")
            .to_string()
            + "…"
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if end_call(&mut tx, &call).await.is_err() {
        return err_db();
    }
    let chat_id = Uuid::new_v4().to_string();
    let stamp = now();
    if sqlx::query("INSERT INTO chats(id,type,name,owner_id,created_at,last_activity) VALUES(?,'group',?,?,?,?)").bind(&chat_id).bind(&group_name).bind(&me.id).bind(&stamp).bind(&stamp).execute(&mut *tx).await.is_err(){return err_db()}
    for id in std::iter::once(&me.id).chain(member_ids.iter()) {
        let seq = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(seq),0) FROM messages WHERE chat_id=?",
        )
        .bind(&chat_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
        if sqlx::query("INSERT INTO chat_members(chat_id,user_id,role,joined_at,joined_seq,cleared_seq,last_read_seq) VALUES(?,?,?, ?,?,0,?)").bind(&chat_id).bind(id).bind(if id==&me.id{"owner"}else{"member"}).bind(now()).bind(seq).bind(seq).execute(&mut *tx).await.is_err(){return err_db()}
    }
    if add_system(
        &mut tx,
        &chat_id,
        "created",
        json!({"actor":me.display_name,"name":group_name}),
    )
    .await
    .is_err()
    {
        return err_db();
    }
    let new_call = match start_call(&mut tx, &chat_id, &me.id).await {
        Ok(v) => v,
        Err(_) => return err_db(),
    };
    if tx.commit().await.is_err() {
        return err_db();
    }
    match serialize_call(&state.db, &new_call, &me.id).await {
        Ok(v) => json_ok(json!({"chat_id":chat_id,"call":v})).into_response(),
        Err(_) => err_db(),
    }
}

async fn ice_servers(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(e) = require_user(&_state, &headers).await {
        return axum::response::IntoResponse::into_response(e);
    }
    let urls = std::env::var("TURN_URLS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let secret = std::env::var("TURN_SECRET").unwrap_or_default();
    let mut servers = Vec::new();
    if !urls.is_empty() && !secret.is_empty() {
        let username = format!(
            "{}:{}",
            chrono::Utc::now().timestamp() + 12 * 3600,
            require_user(&_state, &headers)
                .await
                .ok()
                .and_then(|r| r.try_get::<String, _>("id").ok())
                .unwrap_or_default()
        );
        let mut mac = match Hmac::<Sha1>::new_from_slice(secret.as_bytes()) {
            Ok(v) => v,
            Err(_) => return err_db(),
        };
        mac.update(username.as_bytes());
        servers.push(json!({"urls":urls,"username":username,"credential":STANDARD.encode(mac.finalize().into_bytes())}))
    }
    let stun = std::env::var("STUN_URLS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let stun = if stun.is_empty() {
        urls.first()
            .map(|v| {
                v.replace("turns:", "stun:")
                    .replace("turn:", "stun:")
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .filter(|v| !v.is_empty())
            .map(|v| vec![v])
            .unwrap_or_else(|| vec!["stun:stun.cloudflare.com:3478".into()])
    } else {
        stun
    };
    servers.insert(0, json!({"urls":stun}));
    json_ok(json!({"ice_servers":servers})).into_response()
}

async fn membership(
    pool: &SqlitePool,
    chat: &str,
    user: &str,
) -> Result<Option<SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT c.*,m.role,m.joined_seq,m.cleared_seq,m.last_read_seq,m.hidden,m.pinned,m.archived FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(chat).bind(user).fetch_optional(pool).await
}
async fn member_ids(pool: &SqlitePool, chat: &str) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=?")
        .bind(chat)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| r.try_get("user_id").ok())
        .collect())
}
async fn blocked(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)").bind(a).bind(b).bind(b).bind(a).fetch_optional(pool).await?.is_some())
}
async fn are_friends(pool: &SqlitePool, a: &str, b: &str) -> Result<bool, sqlx::Error> {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    Ok(
        sqlx::query("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?")
            .bind(x)
            .bind(y)
            .fetch_optional(pool)
            .await?
            .is_some(),
    )
}
async fn require_call(
    pool: &SqlitePool,
    id: &str,
    user: &str,
    states: &[&str],
) -> Result<SqliteRow, ()> {
    let call = sqlx::query("SELECT * FROM calls WHERE id=? AND ended_at IS NULL")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ())?;
    let Some(call) = call else { return Err(()) };
    let mine = sqlx::query("SELECT state FROM call_participants WHERE call_id=? AND user_id=?")
        .bind(id)
        .bind(user)
        .fetch_optional(pool)
        .await
        .map_err(|_| ())?;
    if mine
        .and_then(|v| v.try_get::<String, _>("state").ok())
        .is_some_and(|v| states.contains(&v.as_str()))
    {
        Ok(call)
    } else {
        Err(())
    }
}
async fn set_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &str,
    user: &str,
    state: &str,
) -> Result<(), sqlx::Error> {
    let stamp = now();
    sqlx::query("INSERT INTO call_participants(call_id,user_id,state,updated_at,seen_at) VALUES(?,?,?,?,?) ON CONFLICT(call_id,user_id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at,seen_at=excluded.seen_at").bind(call).bind(user).bind(state).bind(&stamp).bind(&stamp).execute(&mut **tx).await?;
    Ok(())
}
async fn leave_other_calls(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    keep: Option<&str>,
) -> Result<(), sqlx::Error> {
    let rows=sqlx::query("SELECT p.call_id FROM call_participants p JOIN calls c ON c.id=p.call_id WHERE p.user_id=? AND p.state='joined' AND c.ended_at IS NULL AND p.call_id!=?").bind(user).bind(keep.unwrap_or("")).fetch_all(&mut **tx).await?;
    for row in rows {
        let id: String = row.try_get("call_id")?;
        set_state(tx, &id, user, "left").await?;
        finish_if_over(tx, &id).await?
    }
    Ok(())
}
async fn start_call(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    caller: &str,
) -> Result<String, sqlx::Error> {
    leave_other_calls(tx, caller, None).await?;
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO calls(id,chat_id,started_by,started_at) VALUES(?,?,?,?)")
        .bind(&id)
        .bind(chat)
        .bind(caller)
        .bind(now())
        .execute(&mut **tx)
        .await?;
    let rows = sqlx::query("SELECT user_id FROM chat_members WHERE chat_id=?")
        .bind(chat)
        .fetch_all(&mut **tx)
        .await?;
    for row in rows {
        let uid: String = row.try_get("user_id")?;
        set_state(
            tx,
            &id,
            &uid,
            if uid == caller { "joined" } else { "ringing" },
        )
        .await?
    }
    Ok(id)
}
async fn finish_if_over(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &str,
) -> Result<(), sqlx::Error> {
    let states = sqlx::query("SELECT state FROM call_participants WHERE call_id=?")
        .bind(call)
        .fetch_all(&mut **tx)
        .await?;
    let joined = states
        .iter()
        .filter(|v| v.try_get::<String, _>("state").ok().as_deref() == Some("joined"))
        .count();
    let ringing = states
        .iter()
        .filter(|v| v.try_get::<String, _>("state").ok().as_deref() == Some("ringing"))
        .count();
    if joined == 0 || (joined == 1 && ringing == 0) {
        finish_call(tx, call).await?
    }
    Ok(())
}
async fn finish_call(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &str,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query("SELECT * FROM calls WHERE id=? AND ended_at IS NULL")
        .bind(call)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else { return Ok(()) };
    let chat: String = row.try_get("chat_id")?;
    let started: Option<String> = row.try_get("answered_at")?;
    let ended = now();
    let seconds = started
        .and_then(|v| {
            chrono::DateTime::parse_from_str(
                &format!("{}+00:00", v.trim_end_matches('Z')),
                "%Y-%m-%dT%H:%M:%S%:z",
            )
            .ok()
        })
        .map(|v| {
            (chrono::Utc::now() - v.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0)
        });
    let caller: String = row.try_get("started_by")?;
    let name = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(NULLIF(display_name,''),username) FROM users WHERE id=?",
    )
    .bind(caller)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_default();
    add_system(tx, &chat, "call", json!({"actor":name,"seconds":seconds})).await?;
    sqlx::query("UPDATE calls SET ended_at=? WHERE id=?")
        .bind(ended.clone())
        .bind(call)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE call_participants SET state='missed',updated_at=? WHERE call_id=? AND state='ringing'").bind(&ended).bind(call).execute(&mut **tx).await?;
    sqlx::query(
        "UPDATE call_participants SET state='left',updated_at=? WHERE call_id=? AND state='joined'",
    )
    .bind(ended)
    .bind(call)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM call_signals WHERE call_id=?")
        .bind(call)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn end_call(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    call: &SqliteRow,
) -> Result<(), sqlx::Error> {
    let id: String = call.try_get("id")?;
    finish_call(tx, &id).await
}
async fn add_system(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chat: &str,
    event: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    let rev: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(rev),0)+1 FROM messages")
        .fetch_one(&mut **tx)
        .await?;
    let mut payload = details.as_object().cloned().unwrap_or_default();
    payload.insert("event".into(), json!(event));
    let stamp = now();
    sqlx::query(
        "INSERT INTO messages(id,chat_id,kind,payload,created_at,rev) VALUES(?,?,'system',?,?,?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(chat)
    .bind(Value::Object(payload).to_string())
    .bind(&stamp)
    .bind(rev)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE chats SET last_activity=? WHERE id=?")
        .bind(stamp)
        .bind(chat)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn expire_calls(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<(), sqlx::Error> {
    let rows=sqlx::query("SELECT p.call_id,p.user_id,p.state FROM call_participants p JOIN calls c ON c.id=p.call_id WHERE c.ended_at IS NULL AND ((p.state='ringing' AND p.updated_at<?) OR (p.state='joined' AND p.seen_at<?))").bind(ago(RING_SECONDS)).bind(ago(GONE_SECONDS)).fetch_all(&mut **tx).await?;
    let mut affected = Vec::new();
    for row in rows {
        let call: String = row.try_get("call_id")?;
        let user: String = row.try_get("user_id")?;
        let state: String = row.try_get("state")?;
        set_state(
            tx,
            &call,
            &user,
            if state == "ringing" { "missed" } else { "left" },
        )
        .await?;
        if !affected.contains(&call) {
            affected.push(call)
        }
    }
    for call in affected {
        finish_if_over(tx, &call).await?
    }
    sqlx::query("DELETE FROM call_signals WHERE created_at<?")
        .bind(ago(120))
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn serialize_call(pool: &SqlitePool, id: &str, me: &str) -> Result<Value, sqlx::Error> {
    let call = sqlx::query("SELECT * FROM calls WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(call) = call else {
        return Err(sqlx::Error::RowNotFound);
    };
    let chat_id: String = call.try_get("chat_id")?;
    let chat = membership(pool, &chat_id, me).await?;
    let name = chat
        .as_ref()
        .and_then(|v| v.try_get::<Option<String>, _>("name").ok().flatten())
        .unwrap_or_default();
    let kind = chat
        .as_ref()
        .and_then(|v| v.try_get::<String, _>("type").ok())
        .unwrap_or_else(|| "dm".into());
    let participants=sqlx::query("SELECT p.user_id,p.state,u.username,u.display_name FROM call_participants p JOIN users u ON u.id=p.user_id WHERE p.call_id=? ORDER BY u.username COLLATE NOCASE").bind(id).fetch_all(pool).await?;
    Ok(
        json!({"id":id,"chat_id":chat_id,"chat_name":name,"chat_type":kind,"started_by":call.try_get::<String,_>("started_by")?,"started_at":call.try_get::<String,_>("started_at")?,"answered_at":call.try_get::<Option<String>,_>("answered_at")?,"participants":participants.iter().map(|r|json!({"id":r.try_get::<String,_>("user_id").unwrap_or_default(),"username":r.try_get::<String,_>("username").unwrap_or_default(),"display_name":r.try_get::<Option<String>,_>("display_name").ok().flatten().filter(|v|!v.is_empty()).or_else(||r.try_get("username").ok()),"state":r.try_get::<String,_>("state").unwrap_or_default()})).collect::<Vec<_>>()}),
    )
}
fn valid_b64(v: &str, max: usize) -> bool {
    let unpadded = v.trim_end_matches('=');
    !v.is_empty()
        && v.len() <= max
        && v.len() - unpadded.len() <= 2
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b))
}
