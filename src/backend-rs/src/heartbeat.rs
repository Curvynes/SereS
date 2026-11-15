//! Uptime heartbeat: with `URL` set (e.g. a Better Stack heartbeat), the
//! backend calls it at startup and then every 10 minutes, so the monitor
//! notices when SereS stops. The URL contains a secret token and is never logged.

use std::time::Duration;

const INTERVAL: Duration = Duration::from_secs(600);

pub fn start() {
    let url = std::env::var("URL").unwrap_or_default().trim().to_owned();
    if url.is_empty() {
        return;
    }
    tokio::spawn(run(url));
}

async fn run(url: String) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(error = %error.without_url(), "heartbeat disabled");
            return;
        }
    };
    let mut ticker = tokio::time::interval(INTERVAL);
    loop {
        // The first tick fires right away.
        ticker.tick().await;
        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => tracing::debug!("heartbeat sent"),
            Ok(response) => {
                tracing::warn!(status = %response.status(), "heartbeat was not accepted")
            }
            Err(error) => tracing::warn!(error = %error.without_url(), "sending heartbeat failed"),
        }
    }
}
