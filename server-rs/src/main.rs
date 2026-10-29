#![recursion_limit = "512"]

mod app;
mod auth;
mod config;
mod db;
mod error;
mod libs;
mod rate_limit;
mod response;
mod routes;
mod shared_state;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{error, info};

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    if let Err(err) = runtime.block_on(run()) {
        error!("server exited with error: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let config = Arc::new(config::Config::from_env()?);
    config::Config::check_jwt_config(&config)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(config.log_level.clone())),
        )
        .finish();

    let pool = db::create_pool(&config).await?;
    info!("postgres pool ready");

    let shared = shared_state::SharedState::connect(config.redis_url.as_deref()).await?;
    if matches!(shared, shared_state::SharedState::Memory(_)) {
        if config.redis_url.is_some() {
            info!("redis unreachable, falling back to in-process shared state");
        } else {
            info!("REDIS_URL not set, using in-process shared state (single replica only)");
        }
    } else {
        info!("redis shared state ready");
    }

    let incus_pool = Arc::new(crate::libs::incus::IncusClientPool::new());
    let state = Arc::new(state::AppState::new(config.clone(), pool, shared, incus_pool));
    let router = app::build_router(state.clone());

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}
