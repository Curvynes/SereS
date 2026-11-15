mod api;
mod db;
mod heartbeat;
mod state;

use anyhow::Result;
use axum::{Router, middleware};
use std::{net::SocketAddr, path::PathBuf};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};

/// Compress only text-like responses: media, PDFs and encrypted attachment
/// bytes don't shrink and would just cost CPU.
fn compressible(
    _: axum::http::StatusCode,
    _: axum::http::Version,
    headers: &axum::http::HeaderMap,
    _: &axum::http::Extensions,
) -> bool {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let large_enough = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_none_or(|len| len >= 1024);
    large_enough
        && (content_type.starts_with("text/html")
            || content_type.starts_with("text/css")
            || content_type.starts_with("text/javascript")
            || content_type.starts_with("application/javascript")
            || content_type.starts_with("application/json")
            || content_type.starts_with("image/svg+xml"))
}

/// Windows 11 may run a window-less background process as "EcoQoS" on its
/// efficiency cores, which made Argon2 (login, registration) 2-5x slower.
/// Opt out, so password hashing always gets full CPU speed.
#[cfg(windows)]
fn disable_power_throttling() {
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
        ProcessPowerThrottling, SetProcessInformation,
    };
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: 0,
    };
    // SAFETY: the pointer and size describe a live, correctly typed struct.
    let ok = unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&state as *const PROCESS_POWER_THROTTLING_STATE).cast(),
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
    };
    if ok == 0 {
        tracing::warn!("could not opt out of Windows power throttling");
    }
}

#[cfg(not(windows))]
fn disable_power_throttling() {}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "seres_backend=info,tower_http=warn".into()),
        )
        .init();
    disable_power_throttling();

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_dir = std::env::var_os("SERES_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../backend"));
    let db_path = data_dir.join("users.db");
    let public_dir = std::env::var_os("SERES_PUBLIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../public"));
    let pool = db::connect(&db_path).await?;
    db::import_legacy(&pool, &data_dir).await?;
    db::migrate_binary_files(&pool, &data_dir).await?;
    db::ensure_server_secret(&pool).await?;
    tokio::spawn(api::chats::scheduled_loop(pool.clone()));
    heartbeat::start();
    let state = state::AppState::new(pool);

    let app = Router::new()
        .merge(api::router())
        .fallback_service(ServeDir::new(public_dir).append_index_html_on_directories(true))
        .with_state(state)
        .layer(middleware::from_fn(api::security_middleware))
        .layer(CompressionLayer::new().compress_when(compressible))
        .layer(TraceLayer::new_for_http());

    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(2222);
    let address: SocketAddr = format!("{host}:{port}").parse()?;
    let mut listeners = vec![(address, TcpListener::bind(address).await?)];
    // An empty value (e.g. "SERES_EXTRA_HOST=" in .env) means no second listener.
    if let Some(extra_host) = std::env::var("SERES_EXTRA_HOST")
        .ok()
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
    {
        let bind_address = if extra_host.contains(':') {
            format!("[{extra_host}]:{port}")
        } else {
            format!("{extra_host}:{port}")
        };
        let extra_address: SocketAddr = bind_address.parse()?;
        if extra_address != address {
            listeners.push((extra_address, TcpListener::bind(extra_address).await?));
        }
    }
    let (shutdown, _) = watch::channel(false);
    let mut servers = JoinSet::new();
    for (address, listener) in listeners {
        tracing::info!(%address, "SereS Rust backend listening");
        let service = app.clone();
        let mut shutdown_rx = shutdown.subscribe();
        servers.spawn(async move {
            axum::serve(
                listener,
                service.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
        });
    }

    let first_server = tokio::select! {
        _ = shutdown_signal() => None,
        result = servers.join_next() => result,
    };
    let _ = shutdown.send(true);
    if let Some(result) = first_server {
        result??;
    }
    while let Some(result) = servers.join_next().await {
        result??;
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "could not register Ctrl+C handler");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "could not register SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
