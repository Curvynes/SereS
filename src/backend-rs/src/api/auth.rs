use super::{ApiError, ApiResult, b64_field, error, json_ok, json_response, str_field};
use crate::state::AppState;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, sqlite::SqliteRow};
use std::{net::SocketAddr, sync::OnceLock};
use uuid::Uuid;

const SESSION_DAYS: i64 = 90;
const DEFAULT_KDF_ITERATIONS: i64 = 600_000;
const MIN_KDF_ITERATIONS: i64 = 100_000;
const MAX_KDF_ITERATIONS: i64 = 5_000_000;
const SESSION_COOKIE: &str = "sessioncookie";
const CONSENT_COOKIE: &str = "cookie_consent";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/prelogin", post(prelogin))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/cookie_consent", post(cookie_consent))
        .route("/api/auth_cookie", get(auth_cookie).post(auth_cookie))
        .route("/api/me", get(me))
        .route("/api/change_password", post(change_password))
        .merge(super::password_reset::router())
}

fn api_bad_request(message: impl Into<String>) -> Response {
    error(message, StatusCode::BAD_REQUEST)
}

pub(crate) async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<SqliteRow> {
    let token = cookie_value(headers, SESSION_COOKIE)?;
    let row = sqlx::query(
        "SELECT u.* FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
    )
    .bind(hash_token(&token))
    .bind(now_iso())
    .fetch_optional(&state.db)
    .await
    .ok()??;
    let last_seen: Option<String> = row.try_get("last_seen").ok().flatten();
    let user_id: String = row.try_get("id").ok()?;
    let now = now_iso();
    if last_seen
        .as_deref()
        .is_none_or(|old| seconds_between(old, &now) >= 20.0)
    {
        let _ = sqlx::query("UPDATE users SET last_seen=? WHERE id=?")
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await;
    }
    Some(row)
}

pub(crate) async fn require_user(state: &AppState, headers: &HeaderMap) -> ApiResult<SqliteRow> {
    current_user(state, headers)
        .await
        .ok_or_else(|| ApiError::new("Not logged in", StatusCode::UNAUTHORIZED))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

pub(crate) fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn iso_after(seconds: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn seconds_between(a: &str, b: &str) -> f64 {
    let parse = |s: &str| {
        chrono::DateTime::parse_from_str(
            &format!("{}+00:00", s.trim_end_matches('Z')),
            "%Y-%m-%dT%H:%M:%S%:z",
        )
        .ok()
    };
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => (b - a).num_milliseconds() as f64 / 1000.0,
        _ => f64::INFINITY,
    }
}

fn password_hasher() -> Argon2<'static> {
    let params = Params::new(65_536, 4, 4, None).expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub(crate) fn hash_password(password: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    password_hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| {
            ApiError::new(
                "Could not hash credential",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
}

pub(crate) fn verify_password(stored: Option<&str>, candidate: &str) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash = stored.unwrap_or_else(|| {
        DUMMY.get_or_init(|| hash_password("constant-time-invalid-user-check").unwrap_or_default())
    });
    let valid = PasswordHash::new(hash).ok().is_some_and(|parsed| {
        password_hasher()
            .verify_password(candidate.as_bytes(), &parsed)
            .is_ok()
    });
    stored.is_some() && valid
}

fn username_valid(value: &str) -> bool {
    (3..=20).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn email_valid(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
}

fn user_display(row: &SqliteRow) -> String {
    row.try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .or_else(|| row.try_get("username").ok())
        .unwrap_or_default()
}

fn public_user(row: &SqliteRow) -> Value {
    json!({ "id": row.try_get::<String,_>("id").unwrap_or_default(),
        "username": row.try_get::<String,_>("username").unwrap_or_default(),
        "display_name": user_display(row) })
}

fn own_user(row: &SqliteRow) -> Value {
    let mut user = public_user(row).as_object().cloned().unwrap_or_default();
    for column in ["email", "pub_ecdh", "pub_sign", "enc_private"] {
        user.insert(
            column.into(),
            row.try_get::<Option<String>, _>(column)
                .ok()
                .flatten()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    user.insert(
        "show_last_seen".into(),
        Value::Bool(row.try_get::<i64, _>("show_last_seen").unwrap_or(1) != 0),
    );
    Value::Object(user)
}

pub(crate) fn validate_kdf(body: &Value) -> ApiResult<(String, i64)> {
    let salt = b64_field(body, "kdf_salt", 64)?.to_owned();
    let iterations = body
        .get("kdf_iterations")
        .and_then(Value::as_i64)
        .filter(|i| (MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(i))
        .ok_or_else(|| ApiError::new("Invalid kdf_iterations", StatusCode::BAD_REQUEST))?;
    Ok((salt, iterations))
}

pub(crate) fn validate_keys(body: &Value) -> ApiResult<(String, String, String)> {
    let keys = body
        .get("keys")
        .filter(|v| v.is_object())
        .ok_or_else(|| ApiError::new("Missing encryption keys", StatusCode::BAD_REQUEST))?;
    Ok((
        b64_field(keys, "pub_ecdh", 512)?.to_owned(),
        b64_field(keys, "pub_sign", 512)?.to_owned(),
        str_field(keys, "enc_private", 8192)?.to_owned(),
    ))
}

fn login_cookie(response: &mut Response, token: &str, headers: &HeaderMap, persistent: bool) {
    let secure = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https");
    let mut cookie = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/");
    if persistent {
        cookie.push_str(&format!("; Max-Age={}", SESSION_DAYS * 24 * 3600));
    }
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    if let Ok(value) = HeaderValue::from_str("username=; Max-Age=0; Path=/") {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn consent_cookie(response: &mut Response, accepted: bool) {
    let value = if accepted { "accepted" } else { "denied" };
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "{CONSENT_COOKIE}={value}; Max-Age={}; SameSite=Lax; Path=/",
        365 * 24 * 3600
    )) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
}

pub(crate) async fn fake_salt(state: &AppState, identifier: &str) -> ApiResult<String> {
    let secret =
        sqlx::query_scalar::<_, String>("SELECT value FROM meta WHERE key='server_secret'")
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                ApiError::new("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR)
            })?;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| ApiError::new("Internal error", StatusCode::INTERNAL_SERVER_ERROR))?;
    hmac::Mac::update(&mut mac, identifier.to_lowercase().as_bytes());
    let digest = hmac::Mac::finalize(mac).into_bytes();
    Ok(STANDARD.encode(&digest[..16]))
}

async fn prelogin(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let name = match str_field(&body, "nameomail", 254) {
        Ok(v) => v.trim(),
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(
        format!("prelogin:{}", super::client_ip(&headers, peer)),
        60,
        60,
    ) {
        return error(
            "Too many attempts, please wait a minute",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let user = sqlx::query(
        "SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE LIMIT 1",
    )
    .bind(name)
    .bind(name)
    .fetch_optional(&state.db)
    .await;
    let user = match user {
        Ok(u) => u,
        Err(_) => return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    };
    let Some(user) = user else {
        return match fake_salt(&state, name).await {
            Ok(salt) => json_ok(
                json!({"kdf_salt":salt,"kdf_iterations":DEFAULT_KDF_ITERATIONS,"legacy":false}),
            ),
            Err(e) => axum::response::IntoResponse::into_response(e),
        };
    };
    let legacy = user.try_get::<i64, _>("auth_version").unwrap_or(0) == 0;
    let existing = user.try_get::<Option<String>, _>("kdf_salt").ok().flatten();
    let user_id: String = user.try_get("id").unwrap_or_default();
    if legacy && existing.is_none() {
        let salt = STANDARD.encode(rand::random::<[u8; 16]>());
        let _ = sqlx::query("UPDATE users SET kdf_salt=?,kdf_iterations=? WHERE id=?")
            .bind(&salt)
            .bind(DEFAULT_KDF_ITERATIONS)
            .bind(&user_id)
            .execute(&state.db)
            .await;
        return json_ok(
            json!({"kdf_salt":salt,"kdf_iterations":DEFAULT_KDF_ITERATIONS,"legacy":true}),
        );
    }
    json_ok(
        json!({"kdf_salt":existing,"kdf_iterations":user.try_get::<Option<i64>,_>("kdf_iterations").ok().flatten().unwrap_or(DEFAULT_KDF_ITERATIONS),"legacy":legacy}),
    )
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let username = match str_field(&body, "username", 64) {
        Ok(v) => v.trim(),
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let email = match str_field(&body, "email", 254) {
        Ok(v) => v.trim(),
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let auth_hash = match b64_field(&body, "auth_hash", 128) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (kdf_salt, kdf_iterations) = match validate_kdf(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (pub_ecdh, pub_sign, enc_private) = match validate_keys(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(
        format!("register:{}", super::client_ip(&headers, peer)),
        10,
        3600,
    ) {
        return error(
            "Too many registrations, please try again later",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    if !username_valid(username) {
        return api_bad_request("Username must be 3-20 characters: letters, numbers, '_' or '-'");
    }
    if !email_valid(email) {
        return api_bad_request("Email is invalid");
    }
    let duplicate = sqlx::query(
        "SELECT 1 FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE",
    )
    .bind(username)
    .bind(email)
    .fetch_optional(&state.db)
    .await;
    match duplicate {
        Ok(Some(_)) => return api_bad_request("Username already taken or email already in use"),
        Ok(None) => {}
        Err(_) => return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    }
    let hashed = match hash_password(auth_hash) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let result=sqlx::query("INSERT INTO users(id,email,username,passwd,auth_version,kdf_salt,kdf_iterations,pub_ecdh,pub_sign,enc_private,created_at) VALUES(?,?,?,?,1,?,?,?,?,?,?)")
        .bind(Uuid::new_v4().to_string()).bind(email).bind(username).bind(hashed).bind(kdf_salt).bind(kdf_iterations).bind(pub_ecdh).bind(pub_sign).bind(enc_private).bind(now_iso()).execute(&state.db).await;
    match result {
        Ok(_) => json_response(
            StatusCode::OK,
            json!({"message":"User created successfully!","success":true}),
        ),
        Err(sqlx::Error::Database(e))
            if e.is_unique_violation() || e.message() == "Email already in use" =>
        {
            api_bad_request("Username already taken or email already in use")
        }
        Err(_) => error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let name = match str_field(&body, "nameomail", 254) {
        Ok(v) => v.trim(),
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let auth_hash = match b64_field(&body, "auth_hash", 128) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    if state.rate_limited(
        format!("login-ip:{}", super::client_ip(&headers, peer)),
        60,
        60,
    ) || state.rate_limited(format!("login-account:{}", name.to_lowercase()), 10, 300)
    {
        return error(
            "Too many login attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let user = sqlx::query(
        "SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE LIMIT 1",
    )
    .bind(name)
    .bind(name)
    .fetch_optional(&state.db)
    .await;
    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            let _ = verify_password(None, auth_hash);
            return api_bad_request("Login not succesfull");
        }
        Err(_) => return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    };
    let id: String = user.try_get("id").unwrap_or_default();
    if user.try_get::<i64, _>("auth_version").unwrap_or(0) == 0 {
        let legacy = body.get("passwd").and_then(Value::as_str);
        let pass = user.try_get::<Option<String>, _>("passwd").ok().flatten();
        if !legacy.is_some_and(|v| verify_password(pass.as_deref(), v)) {
            return api_bad_request("Login not succesfull");
        }
        let (ecdh, sign, enc) = match validate_keys(&body) {
            Ok(v) => v,
            Err(e) => return axum::response::IntoResponse::into_response(e),
        };
        if user
            .try_get::<Option<String>, _>("kdf_salt")
            .ok()
            .flatten()
            .is_none()
        {
            return api_bad_request("Please retry the login");
        }
        let hashed = match hash_password(auth_hash) {
            Ok(v) => v,
            Err(e) => return axum::response::IntoResponse::into_response(e),
        };
        if sqlx::query("UPDATE users SET passwd=?,auth_version=1,pub_ecdh=?,pub_sign=?,enc_private=? WHERE id=?").bind(hashed).bind(ecdh).bind(sign).bind(enc).bind(&id).execute(&state.db).await.is_err(){return error("Database unavailable",StatusCode::INTERNAL_SERVER_ERROR);}
    } else {
        let pass = user.try_get::<Option<String>, _>("passwd").ok().flatten();
        if !verify_password(pass.as_deref(), auth_hash) {
            return api_bad_request("Login not succesfull");
        }
    }
    let totp = user
        .try_get::<Option<String>, _>("totp_secret")
        .ok()
        .flatten()
        .is_some();
    let passkeys = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM passkeys WHERE user_id=?")
        .bind(&id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
        > 0;
    if totp || passkeys {
        let token = Uuid::new_v4().simple().to_string() + &Uuid::new_v4().simple().to_string();
        let token_hash = hash_token(&token);
        let challenge = Uuid::new_v4().simple().to_string();
        let _=sqlx::query("INSERT INTO twofa_challenges(token_hash,user_id,purpose,challenge,attempts,expires_at) VALUES(?,?,'login',?,0,?)")
            .bind(token_hash).bind(&id).bind(challenge).bind(iso_after(300)).execute(&state.db).await;
        return json_ok(
            json!({"two_factor":{"token":token,"methods":{ "totp":totp,"passkey":passkeys },"backup_codes":has_backup_codes(&state,&id).await}}),
        );
    }
    login_response(&state, &id, &headers).await
}

async fn has_backup_codes(state: &AppState, user_id: &str) -> bool {
    sqlx::query("SELECT 1 FROM recovery_codes WHERE user_id=? AND used_at IS NULL")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .is_some()
}

pub(crate) async fn login_response(
    state: &AppState,
    user_id: &str,
    headers: &HeaderMap,
) -> Response {
    let user = match sqlx::query("SELECT * FROM users WHERE id=?")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(v)) => v,
        _ => return error("Account not found", StatusCode::INTERNAL_SERVER_ERROR),
    };
    let token = format!("{}.{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let created = now_iso();
    let expires = iso_after(SESSION_DAYS * 24 * 60 * 60);
    if sqlx::query(
        "INSERT INTO user_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
    )
    .bind(hash_token(&token))
    .bind(user_id)
    .bind(expires)
    .bind(created)
    .execute(&state.db)
    .await
    .is_err()
    {
        return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR);
    }
    let mut response = json_response(
        StatusCode::OK,
        json!({"message":"Login succesfull!","success":true,"user":own_user(&user),"enc_private":user.try_get::<Option<String>,_>("enc_private").ok().flatten()}),
    );
    let persistent = cookie_value(headers, CONSENT_COOKIE).as_deref() == Some("accepted");
    login_cookie(&mut response, &token, headers, persistent);
    response
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        let _ = sqlx::query("DELETE FROM user_sessions WHERE token_hash=?")
            .bind(hash_token(&token))
            .execute(&state.db)
            .await;
    }
    let mut response = json_response(
        StatusCode::OK,
        json!({"message":"Logout succesfull!","success":true}),
    );
    for name in [SESSION_COOKIE, "username"] {
        if let Ok(value) = HeaderValue::from_str(&format!("{name}=; Max-Age=0; Path=/")) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

async fn cookie_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let accepted = body
        .get("accepted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut response = json_response(StatusCode::OK, json!({"success":true,"accepted":accepted}));
    consent_cookie(&mut response, accepted);
    if let (Some(token), Some(_)) = (
        cookie_value(&headers, SESSION_COOKIE),
        current_user(&state, &headers).await,
    ) {
        login_cookie(&mut response, &token, &headers, accepted);
    }
    response
}

async fn auth_cookie(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if current_user(&state, &headers).await.is_none() {
        return api_bad_request("Cookie invalid");
    }
    json_response(
        StatusCode::OK,
        json!({"message":"Cookie valid","success":true}),
    )
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match require_user(&state, &headers).await {
        Ok(user) => json_ok(json!({"user":own_user(&user)})),
        Err(e) => axum::response::IntoResponse::into_response(e),
    }
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let user = match require_user(&state, &headers).await {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let old_hash = match b64_field(&body, "old_auth_hash", 128) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let new_hash = match b64_field(&body, "auth_hash", 128) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let (salt, iterations) = match validate_kdf(&body) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let enc = match str_field(&body, "enc_private", 8192) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let user_id: String = user.try_get("id").unwrap_or_default();
    if state.rate_limited(format!("change-password:{user_id}"), 5, 300) {
        return error(
            "Too many attempts, please wait a few minutes",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let stored = user.try_get::<Option<String>, _>("passwd").ok().flatten();
    if !verify_password(stored.as_deref(), old_hash) {
        return api_bad_request("Current password is wrong");
    }
    let hashed = match hash_password(new_hash) {
        Ok(v) => v,
        Err(e) => return axum::response::IntoResponse::into_response(e),
    };
    let current_hash = hash_token(&cookie_value(&headers, SESSION_COOKIE).unwrap_or_default());
    let mut tx = match state.db.begin().await {
        Ok(v) => v,
        Err(_) => return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR),
    };
    if sqlx::query("UPDATE users SET passwd=?,kdf_salt=?,kdf_iterations=?,enc_private=? WHERE id=?")
        .bind(hashed)
        .bind(salt)
        .bind(iterations)
        .bind(enc)
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR);
    }
    if sqlx::query("DELETE FROM user_sessions WHERE user_id=? AND token_hash!=?")
        .bind(&user_id)
        .bind(current_hash)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR);
    }
    if tx.commit().await.is_err() {
        return error("Database unavailable", StatusCode::INTERNAL_SERVER_ERROR);
    }
    json_response(
        StatusCode::OK,
        json!({"message":"Password changed","success":true}),
    )
}
