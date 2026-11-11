use super::{ApiError, ApiResult, error, json_ok};
use crate::{api::auth::require_user, state::AppState};
use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use image::{ImageFormat, imageops::FilterType};
use sqlx::Row;
use std::io::Cursor;

const MAX_AVATAR_BYTES: usize = 2 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/get_avatar", get(get_own_avatar))
        .route("/api/users/{username}/avatar", get(get_user_avatar))
        .route(
            "/api/chats/{chat_id}/avatar",
            get(get_group_avatar)
                .post(upload_group_avatar)
                .delete(delete_group_avatar),
        )
        .route("/api/upload_avatar", post(upload_avatar))
        .layer(DefaultBodyLimit::max(MAX_AVATAR_BYTES + 128 * 1024))
}

async fn get_own_avatar(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let id: String = user.try_get("id").unwrap_or_default();
    avatar_response(&state, "user_avatars", "user_id", &id).await
}

async fn get_user_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    let viewer = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let viewer_id: String = viewer.try_get("id").unwrap_or_default();
    let other = sqlx::query("SELECT id FROM users WHERE username=? COLLATE NOCASE")
        .bind(username.trim())
        .fetch_optional(&state.db)
        .await;
    let other_id = match other {
        Ok(Some(row)) => row.try_get::<String, _>("id").unwrap_or_default(),
        Ok(None) => return error("No avatar uploaded", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    };
    let allowed = viewer_id == other_id || sqlx::query("SELECT 1 FROM friendships WHERE user_a=MIN(?,?) AND user_b=MAX(?,?) UNION SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id=b.chat_id WHERE a.user_id=? AND b.user_id=? LIMIT 1")
        .bind(&viewer_id).bind(&other_id).bind(&viewer_id).bind(&other_id).bind(&viewer_id).bind(&other_id).fetch_optional(&state.db).await.ok().flatten().is_some();
    if !allowed {
        return error("No avatar uploaded", StatusCode::NOT_FOUND);
    }
    avatar_response(&state, "user_avatars", "user_id", &other_id).await
}

async fn get_group_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let chat=sqlx::query("SELECT c.type FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(&chat_id).bind(&user_id).fetch_optional(&state.db).await;
    match chat {
        Ok(Some(row)) if row.try_get::<String, _>("type").ok().as_deref() == Some("group") => {
            avatar_response(&state, "group_avatars", "chat_id", &chat_id).await
        }
        Ok(Some(_)) => error("Only groups have group pictures", StatusCode::NOT_FOUND),
        Ok(None) => error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}

async fn upload_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let image = match parse_upload(multipart).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    match sqlx::query("INSERT INTO user_avatars(user_id,image,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET image=excluded.image,updated_at=excluded.updated_at").bind(user_id).bind(image).bind(now()).execute(&state.db).await{
        Ok(_)=>json_ok(serde_json::json!({"message":"Image uploaded successfully"})).into_response(),Err(_)=>db_error()
    }
}

async fn upload_group_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
    multipart: Multipart,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let chat=sqlx::query("SELECT c.type,c.owner_id,m.role FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(&chat_id).bind(&user_id).fetch_optional(&state.db).await;
    match chat {
        Ok(Some(row))
            if row.try_get::<String, _>("type").ok().as_deref() == Some("group")
                && (row.try_get::<String, _>("role").ok().as_deref() == Some("owner")
                    || row.try_get::<String, _>("owner_id").ok().as_deref()
                        == Some(user_id.as_str())) => {}
        Ok(Some(_)) => return error("Only the group owner can do this", StatusCode::FORBIDDEN),
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    }
    let image = match parse_upload(multipart).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let updated = uuid::Uuid::new_v4().simple().to_string();
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("INSERT INTO group_avatars(chat_id,image,updated_at) VALUES(?,?,?) ON CONFLICT(chat_id) DO UPDATE SET image=excluded.image,updated_at=excluded.updated_at").bind(&chat_id).bind(image).bind(now()).execute(&mut *tx).await.is_err()||sqlx::query("UPDATE chats SET avatar_updated_at=? WHERE id=?").bind(updated).bind(&chat_id).execute(&mut *tx).await.is_err()||tx.commit().await.is_err(){return db_error()}
    json_ok(serde_json::json!({"message":"Group picture uploaded"})).into_response()
}

async fn delete_group_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(chat_id): Path<String>,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    let chat=sqlx::query("SELECT c.type,c.owner_id,m.role FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE c.id=? AND m.user_id=?").bind(&chat_id).bind(&user_id).fetch_optional(&state.db).await;
    match chat {
        Ok(Some(row))
            if row.try_get::<String, _>("type").ok().as_deref() == Some("group")
                && (row.try_get::<String, _>("role").ok().as_deref() == Some("owner")
                    || row.try_get::<String, _>("owner_id").ok().as_deref()
                        == Some(user_id.as_str())) => {}
        Ok(Some(_)) => return error("Only the group owner can do this", StatusCode::FORBIDDEN),
        Ok(None) => return error("Chat not found", StatusCode::NOT_FOUND),
        Err(_) => return db_error(),
    }
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return db_error(),
    };
    if sqlx::query("DELETE FROM group_avatars WHERE chat_id=?")
        .bind(&chat_id)
        .execute(&mut *tx)
        .await
        .is_err()
        || sqlx::query("UPDATE chats SET avatar_updated_at=NULL WHERE id=?")
            .bind(&chat_id)
            .execute(&mut *tx)
            .await
            .is_err()
        || tx.commit().await.is_err()
    {
        return db_error();
    }
    json_ok(serde_json::json!({"message":"Group picture removed"})).into_response()
}

async fn parse_upload(mut multipart: Multipart) -> ApiResult<Vec<u8>> {
    let mut raw = None;
    while let Some(field) = multipart.next_field().await.map_err(|_| {
        ApiError::new(
            "Wrong filetype (png, jpg, gif or webp)",
            StatusCode::BAD_REQUEST,
        )
    })? {
        if field.name() == Some("avatar_img") {
            if field.file_name().is_none_or(str::is_empty) {
                return Err(ApiError::new("No selected file", StatusCode::BAD_REQUEST));
            }
            let bytes = field.bytes().await.map_err(|_| {
                ApiError::new("File size exceeds 2MB limit", StatusCode::BAD_REQUEST)
            })?;
            if bytes.len() > MAX_AVATAR_BYTES {
                return Err(ApiError::new(
                    "File size exceeds 2MB limit",
                    StatusCode::BAD_REQUEST,
                ));
            }
            raw = Some(bytes.to_vec());
            break;
        }
    }
    let raw = raw.ok_or_else(|| ApiError::new("No selected file", StatusCode::BAD_REQUEST))?;
    let image = image::load_from_memory(&raw).map_err(|_| {
        ApiError::new(
            "Wrong filetype (png, jpg, gif or webp)",
            StatusCode::BAD_REQUEST,
        )
    })?;
    if u64::from(image.width()) * u64::from(image.height()) > 40_000_000 {
        return Err(ApiError::new("Image is too large", StatusCode::BAD_REQUEST));
    }
    let image = image.resize(512, 512, FilterType::Lanczos3).to_rgba8();
    let mut png = Cursor::new(Vec::new());
    image.write_to(&mut png, ImageFormat::Png).map_err(|_| {
        ApiError::new(
            "Wrong filetype (png, jpg, gif or webp)",
            StatusCode::BAD_REQUEST,
        )
    })?;
    Ok(png.into_inner())
}

async fn avatar_response(state: &AppState, table: &str, key: &str, id: &str) -> Response {
    // Table and column identifiers are selected from the fixed endpoint definitions above.
    let sql = format!("SELECT image FROM {table} WHERE {key}=?");
    match sqlx::query_scalar::<_, Vec<u8>>(&sql)
        .bind(id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(image)) => {
            let mut response = Body::from(image).into_response();
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, max-age=300"),
            );
            response
        }
        Ok(None) => error("No avatar uploaded", StatusCode::NOT_FOUND),
        Err(_) => db_error(),
    }
}
fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn db_error() -> Response {
    error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
}
