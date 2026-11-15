mod auth;
mod auth_extra;
mod avatars;
mod calls;
pub(crate) mod chats;
mod password_reset;
mod profile;
mod social;

use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use url::Url;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/online", get(online).post(online))
        .merge(auth::router())
        .merge(auth_extra::router())
        .merge(avatars::router())
        .merge(chats::router())
        .merge(calls::router())
        .merge(profile::router())
        .merge(social::router())
}

async fn online() -> Response {
    Json(json!({"message":"im up", "success":true})).into_response()
}

pub async fn security_middleware(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let is_api = request.uri().path().starts_with("/api/");
    if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        && let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        && !origin_allowed(request.headers(), origin)
    {
        return error("Cross-site request rejected", StatusCode::FORBIDDEN);
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.entry("Content-Security-Policy").or_insert(HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob:; object-src 'self'; frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"));
    headers
        .entry("X-Content-Type-Options")
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry("Referrer-Policy")
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry("X-Frame-Options")
        .or_insert(HeaderValue::from_static("SAMEORIGIN"));
    headers
        .entry("Permissions-Policy")
        .or_insert(HeaderValue::from_static(
            "camera=(), microphone=(self), geolocation=()",
        ));
    if is_api {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    } else {
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-cache"));
    }
    response
}

fn allowed_hosts(headers: &HeaderMap) -> HashSet<String> {
    let mut allowed = HashSet::new();
    for name in ["host", "x-forwarded-host"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            allowed.insert(value.trim().to_ascii_lowercase());
        }
    }
    if let Ok(extra) = std::env::var("SERES_ALLOWED_HOSTS") {
        allowed.extend(
            extra
                .split(',')
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty()),
        );
    }
    allowed
}

fn origin_allowed(headers: &HeaderMap, origin: &str) -> bool {
    Url::parse(origin)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .is_some_and(|url| {
            allowed_hosts(headers).iter().any(|host| {
                Url::parse(&format!("{}://{host}", url.scheme()))
                    .ok()
                    .is_some_and(|allowed| {
                        allowed.host_str() == url.host_str()
                            && allowed.port_or_known_default() == url.port_or_known_default()
                    })
            })
        })
}

/// Forwarded addresses are accepted only from the local reverse proxy.
pub(crate) fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        for name in ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"] {
            if let Some(ip) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
            {
                return ip;
            }
        }
    }
    peer.ip()
}

pub fn json_ok(value: Value) -> Response {
    let mut body = value.as_object().cloned().unwrap_or_default();
    body.insert("success".into(), Value::Bool(true));
    json_response(StatusCode::OK, Value::Object(body))
}

pub fn error(message: impl Into<String>, status: StatusCode) -> Response {
    json_response(status, json!({"message": message.into(), "success": false}))
}

#[derive(Debug)]
pub struct ApiError {
    message: String,
    status: StatusCode,
}

impl ApiError {
    pub fn new(message: impl Into<String>, status: StatusCode) -> Self {
        Self {
            message: message.into(),
            status,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error(self.message, self.status)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn json_response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

pub fn str_field<'a>(body: &'a Value, name: &str, max_len: usize) -> ApiResult<&'a str> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.chars().count() <= max_len)
        .ok_or_else(|| {
            ApiError::new(
                format!("Missing or invalid '{name}'"),
                StatusCode::BAD_REQUEST,
            )
        })
}

pub fn b64_field<'a>(body: &'a Value, name: &str, max_len: usize) -> ApiResult<&'a str> {
    let value = str_field(body, name, max_len)?;
    let unpadded = value.trim_end_matches('=');
    let padding = value.len() - unpadded.len();
    let valid = padding <= 2
        && unpadded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/_-".contains(&b));
    if !valid {
        return Err(ApiError::new(
            format!("Invalid encoding of '{name}'"),
            StatusCode::BAD_REQUEST,
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_checks_preserve_ports_and_support_ipv6_and_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:2222".parse().unwrap());
        assert!(origin_allowed(&headers, "http://localhost:2222"));
        assert!(!origin_allowed(&headers, "http://localhost:3333"));
        assert!(!origin_allowed(&headers, "http://other.example:2222"));
        assert!(!origin_allowed(&headers, "null"));
        headers.insert("host", "[::1]:2222".parse().unwrap());
        assert!(origin_allowed(&headers, "http://[::1]:2222"));
        headers.insert("x-forwarded-host", "chat.example:443".parse().unwrap());
        assert!(origin_allowed(&headers, "https://chat.example"));
        assert!(!origin_allowed(&headers, "https://chat.example:444"));
    }

    #[tokio::test]
    async fn proxy_clients_have_independent_limits_and_remote_headers_are_ignored() {
        let peer = "127.0.0.1:9000".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.2".parse().unwrap(),
        );
        let ip = client_ip(&headers, peer);
        assert_eq!(ip.to_string(), "203.0.113.2");
        headers.insert("cf-connecting-ip", "203.0.113.3".parse().unwrap());
        let other_ip = client_ip(&headers, peer);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_lazy("sqlite::memory:")
            .unwrap();
        let state = AppState::new(pool);
        assert!(!state.rate_limited(format!("login-ip:{ip}"), 1, 60));
        assert!(state.rate_limited(format!("login-ip:{ip}"), 1, 60));
        assert!(!state.rate_limited(format!("login-ip:{other_ip}"), 1, 60));
        let remote = "198.51.100.10:9000".parse().unwrap();
        assert_eq!(client_ip(&headers, remote), remote.ip());
    }
}
