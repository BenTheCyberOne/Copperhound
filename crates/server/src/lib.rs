//! CopperHound server: REST API (`/api/v1`) plus the static web UI.
//!
//! One process, no external database: graphs are memory-mapped CopperHound
//! stores in `<data>/graphs`, uploads in `<data>/uploads`, operator marks in
//! `<data>/marks.json`. An ingest job rebuilds the graph from all uploads and
//! hot-swaps it without downtime.

pub mod alerts;
pub mod analysis;
pub mod api;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod collectors;
pub mod compat;
pub mod dbadmin;
pub mod env;
pub mod hmac_auth;
pub mod kindstyle;
pub mod ldapcollect;
pub mod mfa;
pub mod network;
pub mod notify;
pub mod quality;
pub mod risk;
pub mod saml;
pub mod samlxml;
pub mod schedule;
pub mod sso;
pub mod state;
pub mod tickets;
pub mod tls;
pub mod users;
pub mod watch;
pub mod zonereview;

use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;
use state::AppState;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Built web UI (`web/dist`). `None` serves the API only.
    pub web_dir: Option<PathBuf>,
}

pub fn router(st: Arc<AppState>) -> Router {
    let authed = Router::new()
        .route("/logout", post(api::logout))
        .route("/me", get(users::me))
        .route("/me/password", axum::routing::put(users::change_password))
        .route("/me/mfa", get(users::mfa_status))
        .route("/me/mfa/setup", post(users::mfa_setup))
        .route("/me/mfa/enable", post(users::mfa_enable))
        .route("/me/mfa/disable", post(users::mfa_disable))
        .route("/me/tokens", get(users::list_my_tokens).post(users::create_my_token))
        .route("/me/tokens/{id}", delete(users::delete_my_token))
        .route("/users", get(users::list_users).post(users::create_user))
        .route("/users/{name}", axum::routing::put(users::update_user).delete(users::delete_user))
        .route("/users/{name}/tokens/{id}", delete(users::revoke_user_token))
        .route("/users/{name}/mfa", delete(users::reset_user_mfa))
        .route("/audit", get(users::audit))
        .route("/settings", get(watch::get_settings).put(watch::put_settings))
        .route("/stats", get(api::stats))
        .route("/search", get(api::search))
        .route("/nodes", get(api::nodes_batch))
        .route("/nodes/resolve", post(api::resolve_nodes))
        .route("/nodes/filter", post(api::filter_nodes))
        .route("/columns", get(api::columns))
        .route("/subgraph", post(api::subgraph))
        .route("/nodes/{id}", get(api::node))
        .route("/nodes/{id}/edges", get(api::node_edges))
        .route("/nodes/{id}/marks", post(api::mark))
        .route("/path", post(api::path))
        .route("/tier0", get(api::tier0))
        .route("/query", post(api::query))
        .route("/query/{id}", delete(api::cancel_query))
        .route("/queries", get(api::queries))
        .route("/saved-queries", get(api::list_saved).post(api::create_saved))
        .route("/saved-queries/{id}", axum::routing::put(api::update_saved).delete(api::delete_saved))
        .route("/findings", get(analysis::findings))
        .route("/findings-involving", get(analysis::findings_involving))
        .route("/zones/membership", post(analysis::zone_membership))
        .route("/findings/{id}", get(analysis::finding))
        .route("/simulate", post(analysis::simulate_api))
        .route("/remediation-plan", post(analysis::plan_api))
        .route("/zones", get(analysis::list_zones).post(analysis::create_zone))
        .route("/zones/{id}", axum::routing::put(analysis::update_zone).delete(analysis::delete_zone))
        .route("/zones/{id}/members", get(analysis::zone_members_api))
        .route("/zones/{id}/review", get(zonereview::get_review).post(zonereview::post_review))
        .route("/zones/{id}/exposure", get(analysis::zone_exposure))
        .route("/network", get(network::get_network).put(network::put_network).delete(network::delete_network))
        .route("/network/exposure", get(network::network_exposure))
        .route("/report", get(analysis::report))
        .route("/posture", get(analysis::posture))
        .route("/posture/diff", get(analysis::posture_diff))
        .route("/posture/{id}", delete(analysis::delete_snapshot))
        .route("/edge-kinds", get(api::edge_kinds))
        .route("/edges/composition", get(api::edge_composition))
        .route("/database/clear", post(dbadmin::clear))
        .route("/backup", get(backup::backup))
        .route("/restore", post(backup::restore).layer(DefaultBodyLimit::disable()))
        .route("/quality", get(quality::quality))
        .route("/kind-styles", get(kindstyle::get_styles).put(kindstyle::put_styles))
        .route("/environments", get(analysis::environments))
        .route("/collectors", get(collectors::list).post(collectors::create))
        .route("/collectors/{id}", delete(collectors::delete))
        .route("/collect/ldap", get(ldapcollect::list).put(ldapcollect::upsert))
        .route("/collect/ldap/{id}", delete(ldapcollect::remove))
        .route("/collect/ldap/{id}/run", post(ldapcollect::run_now))
        .route("/collect/ldap/{id}/test", post(ldapcollect::test))
        .route("/findings/accepted", get(risk::list))
        .route("/findings/{id}/history", get(analysis::finding_history))
        .route("/findings/{id}/acceptance", axum::routing::put(risk::accept).delete(risk::revoke))
        .route("/node-kinds", get(api::node_kinds))
        .route("/upload", post(api::upload).layer(DefaultBodyLimit::disable()))
        .route("/uploads", get(api::list_uploads))
        .route("/sources", get(api::sources))
        .route("/uploads/{name}", delete(api::delete_upload))
        .route("/ingest", post(api::start_ingest))
        .route("/jobs", get(api::jobs))
        .route("/jobs/{id}", get(api::job))
        // Notifications, scheduled reports and change alerts (notify.rs, schedule.rs, alerts.rs).
        .route("/notify/channels", get(notify::get_channels).put(notify::put_channels))
        .route("/notify/channels/{id}/test", post(notify::test_channel))
        // Remediation hand-off (tickets.rs).
        .route("/remediation/commands", post(tickets::commands))
        .route("/tickets", get(tickets::list).post(tickets::create))
        .route("/tickets/targets", get(tickets::get_targets).put(tickets::put_targets))
        .route("/tickets/targets/{id}/test", post(tickets::test_target))
        .route("/schedules", get(schedule::list).post(schedule::create))
        .route("/schedules/{id}", axum::routing::put(schedule::update).delete(schedule::remove))
        .route("/schedules/{id}/run", post(schedule::run_now))
        .route("/alerts/rules", get(alerts::get_rules).put(alerts::put_rules))
        .route("/alerts", get(alerts::history))
        .merge(sso::admin_routes())
        .merge(saml::admin_routes())
        .route_layer(axum::middleware::from_fn_with_state(st.clone(), api::require_auth));
    let api = Router::new()
        .route("/health", get(api::health))
        .route("/login", post(api::login))
        .merge(sso::public_routes())
        .merge(saml::public_routes())
        .merge(authed)
        .fallback(|| async { api::ApiError::new(axum::http::StatusCode::NOT_FOUND, "no such endpoint") });

    // BloodHound CE-compatible subset (compat.rs).
    let v2_authed = Router::new()
        .route("/file-upload", get(compat::list))
        .route("/file-upload/start", post(compat::start))
        .route("/file-upload/{id}", post(compat::upload_file).layer(DefaultBodyLimit::disable()))
        .route("/file-upload/{id}/end", post(compat::end))
        .route("/custom-nodes", post(kindstyle::bh_custom_nodes))
        .route_layer(axum::middleware::from_fn_with_state(st.clone(), api::require_auth));
    let v2 = Router::new()
        .route("/login", post(compat::login))
        .merge(v2_authed)
        .fallback(|| async { api::ApiError::new(axum::http::StatusCode::NOT_FOUND, "no such endpoint") });

    let mut app = Router::new().nest("/api/v1", api).nest("/api/v2", v2);
    if let Some(web) = &st.web_dir {
        let index = web.join("index.html");
        // `fallback` (not `not_found_service`) so client-side routes get 200 + index.html.
        app = app.fallback_service(ServeDir::new(web).fallback(ServeFile::new(index)));
    }
    app.layer(CompressionLayer::new()).layer(TraceLayer::new_for_http()).with_state(st)
}

pub async fn serve(cfg: ServerConfig) -> Result<()> {
    let web_dir = cfg.web_dir.filter(|d| d.join("index.html").exists());
    if web_dir.is_none() {
        tracing::warn!("web UI not found; serving the API only");
    }
    let (st, generated) = AppState::new(cfg.data_dir.clone(), web_dir)?;
    if let Some(p) = generated {
        // Shown once, like a first-boot credential; also saved in the data dir.
        tracing::info!("################################################################");
        tracing::info!("#  Initial admin password: {p}");
        tracing::info!("#  (stored in {})", cfg.data_dir.join("admin_password").display());
        tracing::info!("################################################################");
    }
    watch::spawn(&st);
    schedule::spawn(&st);
    ldapcollect::spawn(&st);
    if backup::take_ingest_marker(&cfg.data_dir) {
        match api::queue_ingest(&st, "restore") {
            Ok(id) => tracing::info!("rebuilding the graph from the restored uploads (job {id})"),
            Err(_) => tracing::warn!("could not queue the rebuild after restore (an ingest is already running)"),
        }
    }
    let tls = tls::from_env(&cfg.data_dir)?;
    let app = router(st);
    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    let Some(files) = tls else {
        tracing::info!("CopperHound listening on http://{}", cfg.listen);
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        return Ok(());
    };
    let acceptor = Arc::new(tls::Reloading::new(files.clone())?);
    sso::TLS_ON.store(true, std::sync::atomic::Ordering::Relaxed);
    let app = app.layer(axum::middleware::map_response(|mut res: axum::response::Response| async move {
        res.headers_mut()
            .insert(axum::http::header::STRICT_TRANSPORT_SECURITY, axum::http::HeaderValue::from_static("max-age=31536000"));
        res
    }));
    tracing::info!("CopperHound listening on https://{} (certificate {})", cfg.listen, files.cert.display());
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => {
                let Ok((tcp, addr)) = r else { continue };
                let acc = acceptor.acceptor();
                let app = app.clone();
                tokio::spawn(async move {
                    let Ok(Ok(stream)) = tokio::time::timeout(std::time::Duration::from_secs(10), acc.accept(tcp)).await else { return };
                    let svc = app.layer(axum::Extension(axum::extract::ConnectInfo(addr)));
                    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), hyper_util::service::TowerToHyperService::new(svc))
                        .await;
                });
            }
        }
    }
    Ok(())
}

/// Ctrl-C, or SIGTERM on Unix (`docker stop`).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}

pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn")))
        .try_init();
}
