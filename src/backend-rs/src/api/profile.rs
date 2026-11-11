use super::{error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::Row;
use std::collections::HashMap;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/users/keys", get(user_keys))
        .route("/api/profile/display_name", post(set_display_name))
        .route("/api/profile/privacy", post(set_privacy))
}

async fn user_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if let Err(e) = require_user(&state, &headers).await {
        return axum::response::IntoResponse::into_response(e);
    }
    let ids = query
        .get("ids")
        .map(|s| {
            s.split(',')
                .filter(|id| !id.is_empty())
                .take(100)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        return json_ok(json!({"users":[]})).into_response();
    }
    let marks = vec!["?"; ids.len()].join(",");
    let sql = format!(
        "SELECT id,username,display_name,pub_ecdh,pub_sign FROM users WHERE id IN ({marks})"
    );
    let mut users_query = sqlx::query(&sql);
    for id in &ids {
        users_query = users_query.bind(id)
    }
    let rows = match users_query.fetch_all(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let history_sql = format!(
        "SELECT user_id,pub_ecdh,pub_sign,replaced_at FROM user_key_history WHERE user_id IN ({marks}) ORDER BY replaced_at"
    );
    let mut history_query = sqlx::query(&history_sql);
    for id in &ids {
        history_query = history_query.bind(id)
    }
    let history_rows = match history_query.fetch_all(&state.db).await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    let mut history: HashMap<String, Vec<Value>> = HashMap::new();
    for row in history_rows {
        let id: String = row.try_get("user_id").unwrap_or_default();
        history.entry(id).or_default().push(json!({"pub_ecdh":row.try_get::<String,_>("pub_ecdh").unwrap_or_default(),"pub_sign":row.try_get::<String,_>("pub_sign").unwrap_or_default(),"until":row.try_get::<String,_>("replaced_at").unwrap_or_default()}))
    }
    let users=rows.iter().map(|row|{let id:String=row.try_get("id").unwrap_or_default();json!({"id":id,"username":row.try_get::<String,_>("username").unwrap_or_default(),"display_name":row.try_get::<Option<String>,_>("display_name").ok().flatten().filter(|s|!s.is_empty()).or_else(||row.try_get("username").ok()),"pub_ecdh":row.try_get::<Option<String>,_>("pub_ecdh").ok().flatten(),"pub_sign":row.try_get::<Option<String>,_>("pub_sign").ok().flatten(),"previous_keys":history.remove(&id).unwrap_or_default()})}).collect::<Vec<_>>();
    json_ok(json!({"users":users})).into_response()
}

async fn set_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let username: String = user.try_get("username").unwrap_or_default();
    let value = body.get("display_name");
    if value.is_some_and(|v| !v.is_null() && !v.is_string()) {
        return error("Invalid display name", StatusCode::BAD_REQUEST);
    }
    let normalized = value
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.chars().count() > 32 {
        return error(
            "Display name can be at most 32 characters",
            StatusCode::BAD_REQUEST,
        );
    }
    let stored = if normalized.is_empty() {
        None
    } else {
        Some(normalized.as_str())
    };
    match sqlx::query("UPDATE users SET display_name=? WHERE id=?")
        .bind(stored)
        .bind(user.try_get::<String, _>("id").unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"display_name":stored.unwrap_or(&username)})).into_response(),
        Err(_) => db_error(),
    }
}
async fn set_privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let Some(show) = body.get("show_last_seen").and_then(Value::as_bool) else {
        return error("Invalid 'show_last_seen'", StatusCode::BAD_REQUEST);
    };
    match sqlx::query("UPDATE users SET show_last_seen=? WHERE id=?")
        .bind(i64::from(show))
        .bind(user.try_get::<String, _>("id").unwrap_or_default())
        .execute(&state.db)
        .await
    {
        Ok(_) => json_ok(json!({"show_last_seen":show})).into_response(),
        Err(_) => db_error(),
    }
}
fn db_error() -> axum::response::Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
use axum::response::IntoResponse;
