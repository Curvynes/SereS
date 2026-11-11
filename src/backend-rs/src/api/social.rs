use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use rand::{Rng, distributions::Alphanumeric};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/friends", get(list_friends))
        .route("/api/pending_friends", get(pending_friends_legacy))
        .route("/api/friends/request", post(request_friend))
        .route("/api/add_friend", post(request_friend))
        .route("/api/invite", get(my_invite))
        .route("/api/invite/renew", post(renew_invite))
        .route("/api/invite/{token}", get(show_invite))
        .route("/api/invite/{token}/accept", post(accept_invite))
        .route("/api/friends/accept", post(accept_friend))
        .route("/api/friends/decline", post(decline_friend))
        .route("/api/discard_request", post(decline_friend))
        .route("/api/friends/cancel", post(cancel_friend_request))
        .route("/api/friends/remove", post(remove_friend))
        .route("/api/block", post(block_user))
        .route("/api/block_user", post(block_user))
        .route("/api/unblock", post(unblock_user))
        .route("/api/users/mute", post(mute_user))
        .route("/api/users/{username}/profile", get(user_profile))
}

async fn pending_friends_legacy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("SELECT u.username FROM friend_requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=?").bind(me).fetch_all(&state.db).await{Ok(rows)=>json_ok(json!({"pending_friends":rows.iter().filter_map(|r|r.try_get::<String,_>("username").ok()).collect::<Vec<_>>()})).into_response(),Err(_)=>db_error()}
}

async fn list_friends(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let friends = sqlx::query("SELECT u.id,u.username,u.display_name FROM friendships f JOIN users u ON u.id=CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END WHERE f.user_a=? OR f.user_b=? ORDER BY COALESCE(u.display_name,u.username) COLLATE NOCASE")
        .bind(&me).bind(&me).bind(&me).fetch_all(&state.db).await;
    let incoming = sqlx::query("SELECT u.id,u.username,u.display_name FROM friend_requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=? ORDER BY r.created_at")
        .bind(&me).fetch_all(&state.db).await;
    let outgoing = sqlx::query("SELECT u.id,u.username,u.display_name FROM friend_requests r JOIN users u ON u.id=r.to_id WHERE r.from_id=? ORDER BY r.created_at")
        .bind(&me).fetch_all(&state.db).await;
    let blocked = sqlx::query("SELECT u.id,u.username,u.display_name FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=? ORDER BY u.username COLLATE NOCASE")
        .bind(&me).fetch_all(&state.db).await;
    match (friends, incoming, outgoing, blocked) {
        (Ok(f), Ok(i), Ok(o), Ok(b)) => json_ok(
            json!({"friends":users(f),"incoming":users(i),"outgoing":users(o),"blocked":users(b)}),
        )
        .into_response(),
        _ => error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn request_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    send_friend_request(&state, &me, &other).await
}

async fn send_friend_request(state: &AppState, me: &str, other: &str) -> axum::response::Response {
    if state.rate_limited(format!("friend-request:{me}"), 30, 600) {
        return error(
            "Too many friend requests, please wait",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    if me == other {
        return error("Cannot add yourself as a friend", StatusCode::BAD_REQUEST);
    }
    if are_friends(&state.db, me, other).await.unwrap_or(false) {
        return error("Already Friends", StatusCode::BAD_REQUEST);
    }
    if is_blocked(&state.db, me, other).await.unwrap_or(true) {
        return error("Friend request could not be sent", StatusCode::BAD_REQUEST);
    }
    if exists(
        &state.db,
        "SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
        other,
        me,
    )
    .await
    {
        let mut tx = match state.db.begin().await {
            Ok(v) => v,
            Err(_) => return db_error(),
        };
        let (a, b) = pair(me, other);
        if sqlx::query("INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,?)").bind(a).bind(b).bind(now()).execute(&mut *tx).await.is_err()
            || sqlx::query("DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)").bind(me).bind(other).bind(other).bind(me).execute(&mut *tx).await.is_err()
            || tx.commit().await.is_err(){return db_error()}
        return json_ok(json!({"message":"Friend added successfully!","status":"friends"}))
            .into_response();
    }
    if exists(
        &state.db,
        "SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
        me,
        other,
    )
    .await
    {
        return error("Already pending request", StatusCode::BAD_REQUEST);
    }
    match sqlx::query("INSERT INTO friend_requests(from_id,to_id,created_at) VALUES(?,?,?)")
        .bind(me)
        .bind(other)
        .bind(now())
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"message":"Request sent","status":"pending"})).into_response(),
        Err(_) => db_error(),
    }
}

async fn my_invite(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    invite_response(&state, &headers, false).await
}
async fn renew_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    invite_response(&state, &headers, true).await
}
async fn invite_response(
    state: &AppState,
    headers: &HeaderMap,
    renew: bool,
) -> axum::response::Response {
    let me = match user_id(state, headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if !renew
        && let Ok(Some(token)) =
            sqlx::query_scalar::<_, String>("SELECT token FROM friend_invites WHERE user_id=?")
                .bind(&me)
                .fetch_optional(&state.db)
                .await
    {
        return json_ok(json!({"token":token})).into_response();
    }
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(22)
        .map(char::from)
        .collect();
    match sqlx::query("INSERT INTO friend_invites(token,user_id,created_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token,created_at=excluded.created_at").bind(&token).bind(me).bind(now()).execute(&state.db).await{
        Ok(_)=>json_ok(json!({"token":token})).into_response(),Err(_)=>db_error()
    }
}

async fn show_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let owner = match invite_owner(&state, &token).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let status = if owner.0 == me {
        "self"
    } else if are_friends(&state.db, &me, &owner.0).await.unwrap_or(false) {
        "friends"
    } else {
        "none"
    };
    json_ok(json!({"user":owner.1,"status":status})).into_response()
}
async fn accept_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let owner = match invite_owner(&state, &token).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    send_friend_request(&state, &me, &owner.0).await
}
async fn invite_owner(state: &AppState, token: &str) -> ApiResult<(String, Value)> {
    let row=sqlx::query("SELECT u.id,u.username,u.display_name FROM friend_invites i JOIN users u ON u.id=i.user_id WHERE i.token=?").bind(token.chars().take(64).collect::<String>()).fetch_optional(&state.db).await.map_err(|_|ApiError::new("Database unavailable",StatusCode::INTERNAL_SERVER_ERROR))?.ok_or_else(||ApiError::new("This invite link is invalid or expired",StatusCode::NOT_FOUND))?;
    let id: String = row.try_get("id").unwrap_or_default();
    Ok((id, public_user(&row)))
}

async fn accept_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if !exists(
        &state.db,
        "SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?",
        &other,
        &me,
    )
    .await
    {
        return error("Request doesnt exist", StatusCode::BAD_REQUEST);
    }
    make_friends(&state.db, &me, &other)
        .await
        .map(|_| json_ok(json!({"message":"Friend added successfully!"})).into_response())
        .unwrap_or_else(|_| db_error())
}
async fn decline_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("DELETE FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(&other)
        .bind(&me)
        .execute(&state.db)
        .await
    {
        Ok(v) if v.rows_affected() > 0 => {
            json_ok(json!({"message":"successfully deleted the request"})).into_response()
        }
        Ok(_) => error("Request doesnt exist", StatusCode::BAD_REQUEST),
        Err(_) => db_error(),
    }
}
async fn cancel_friend_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("DELETE FROM friend_requests WHERE from_id=? AND to_id=?")
        .bind(&me)
        .bind(other)
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"message":"Request cancelled"})).into_response(),
        Err(_) => db_error(),
    }
}
async fn remove_friend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (a, b) = pair(&me, &other);
    match sqlx::query("DELETE FROM friendships WHERE user_a=? AND user_b=?")
        .bind(a)
        .bind(b)
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"message":"Friend removed"})).into_response(),
        Err(_) => db_error(),
    }
}
async fn block_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if me == other {
        return error("Cannot block yourself", StatusCode::BAD_REQUEST);
    }
    let was_friend = are_friends(&state.db, &me, &other).await.unwrap_or(false) as i64;
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query(
        "INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at,was_friend) VALUES(?,?,?,?)",
    )
    .bind(&me)
    .bind(&other)
    .bind(now())
    .bind(was_friend)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return db_error();
    }
    let (a, b) = pair(&me, &other);
    if sqlx::query("DELETE FROM friendships WHERE user_a=? AND user_b=?")
        .bind(a)
        .bind(b)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query(
            "DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
        )
        .bind(&me)
        .bind(&other)
        .bind(&other)
        .bind(&me)
        .execute(&mut *tx)
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(json!({"message":"User blocked"})).into_response()
}
async fn unblock_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let row = sqlx::query("SELECT was_friend FROM blocks WHERE blocker_id=? AND blocked_id=?")
        .bind(&me)
        .bind(&other)
        .fetch_optional(&state.db)
        .await;
    let was_friend = match row {
        Ok(v) => {
            v.and_then(|r| r.try_get::<i64, _>("was_friend").ok())
                .unwrap_or(0)
                != 0
        }
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM blocks WHERE blocker_id=? AND blocked_id=?")
        .bind(&me)
        .bind(&other)
        .execute(&state.db)
        .await
        .is_err()
    {
        return db_error();
    }
    let restored = was_friend && !is_blocked(&state.db, &me, &other).await.unwrap_or(true);
    if restored && make_friends(&state.db, &me, &other).await.is_err() {
        return db_error();
    }
    json_ok(json!({"message":"User unblocked","friends":restored})).into_response()
}
async fn mute_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = match target_user(&state, &body).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let muted = body.get("muted").and_then(Value::as_bool) == Some(true);
    let query = if muted {
        "INSERT OR IGNORE INTO muted_users(user_id,muted_id,created_at) VALUES(?,?,?)"
    } else {
        "DELETE FROM muted_users WHERE user_id=? AND muted_id=?"
    };
    let mut q = sqlx::query(query).bind(&me).bind(&other);
    if muted {
        q = q.bind(now())
    }
    match q.execute(&state.db).await {
        Ok(_) => json_ok(json!({"muted":muted})).into_response(),
        Err(_) => db_error(),
    }
}
async fn user_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> axum::response::Response {
    let me = match user_id(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let other = sqlx::query("SELECT * FROM users WHERE username=? COLLATE NOCASE")
        .bind(username.trim())
        .fetch_optional(&state.db)
        .await;
    let other = match other {
        Ok(Some(u)) => u,
        Ok(None) => return error("User not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let oid: String = other.try_get("id").unwrap_or_default();
    let is_me = oid == me;
    let req=sqlx::query("SELECT from_id FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)").bind(&me).bind(&oid).bind(&oid).bind(&me).fetch_optional(&state.db).await;
    let request = match req {
        Ok(Some(r)) => Some(
            if r.try_get::<String, _>("from_id").ok().as_deref() == Some(me.as_str()) {
                "outgoing"
            } else {
                "incoming"
            },
        ),
        Ok(None) => None,
        Err(_) => return db_error(),
    };
    let friend = are_friends(&state.db, &me, &oid).await.unwrap_or(false);
    let blocked = exists(
        &state.db,
        "SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?",
        &me,
        &oid,
    )
    .await;
    let muted = exists(
        &state.db,
        "SELECT 1 FROM muted_users WHERE user_id=? AND muted_id=?",
        &me,
        &oid,
    )
    .await;
    let can_see = friend || exists(&state.db, "SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id=b.chat_id WHERE a.user_id=? AND b.user_id=? LIMIT 1", &me, &oid).await;
    let presence = if !is_me && can_see {
        let visibility=sqlx::query("SELECT v.show_last_seen viewer_show,o.show_last_seen other_show,o.last_seen FROM users v JOIN users o ON o.id=? WHERE v.id=?").bind(&oid).bind(&me).fetch_optional(&state.db).await;
        match visibility {
            Ok(Some(r)) => {
                let show = r.try_get::<i64, _>("viewer_show").unwrap_or(1) != 0
                    && r.try_get::<i64, _>("other_show").unwrap_or(1) != 0;
                let last = r.try_get::<Option<String>, _>("last_seen").ok().flatten();
                if show {
                    last.map(|last| json!({"online":online(&last),"last_seen":last}))
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(_) => return db_error(),
        }
    } else {
        None
    };
    json_ok(json!({"user":{"id":oid,"username":other.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(&other),"pub_ecdh":other.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":other.try_get::<Option<String>,_>("pub_sign").ok().flatten()},"is_me":is_me,"friend":friend,"blocked":blocked,"muted":muted,"request":request,"presence":presence})).into_response()
}

async fn user_id(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let row = require_user(state, headers).await?;
    Ok(row.try_get("id").unwrap_or_default())
}
async fn target_user(state: &AppState, body: &Value) -> ApiResult<String> {
    let name = body
        .get("username")
        .or_else(|| body.get("friend_username"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ApiError::new("Missing or invalid 'username'", StatusCode::BAD_REQUEST))?;
    sqlx::query_scalar("SELECT id FROM users WHERE username=? COLLATE NOCASE")
        .bind(name.trim())
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::new("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or_else(|| ApiError::new("User not found", StatusCode::NOT_FOUND))
}
fn users(rows: Vec<sqlx::sqlite::SqliteRow>) -> Vec<Value> {
    rows.iter().map(public_user).collect()
}
fn public_user(row: &sqlx::sqlite::SqliteRow) -> Value {
    json!({"id":row.try_get::<String,_>("id").unwrap_or_default(),"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":display_name(row)})
}
fn display_name(row: &sqlx::sqlite::SqliteRow) -> String {
    row.try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .or_else(|| row.try_get("username").ok())
        .unwrap_or_default()
}
fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn online(last: &str) -> bool {
    chrono::DateTime::parse_from_str(
        &format!("{}+00:00", last.trim_end_matches('Z')),
        "%Y-%m-%dT%H:%M:%S%:z",
    )
    .ok()
    .is_some_and(|d| (chrono::Utc::now() - d.with_timezone(&chrono::Utc)).num_seconds() < 45)
}
async fn exists(pool: &SqlitePool, sql: &str, a: &str, b: &str) -> bool {
    sqlx::query(sql)
        .bind(a)
        .bind(b)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
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
async fn make_friends(pool: &SqlitePool, a: &str, b: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let (x, y) = pair(a, b);
    sqlx::query("INSERT OR IGNORE INTO friendships(user_a,user_b,created_at) VALUES(?,?,?)")
        .bind(x)
        .bind(y)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM friend_requests WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?)",
    )
    .bind(a)
    .bind(b)
    .bind(b)
    .bind(a)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}
fn db_error() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
use axum::response::IntoResponse;
