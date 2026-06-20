//! attestation-portal server — receives pushed node reports + serves them (+ later: verify, page, /admin).
//!
//! PUSH model (../SECURITY.md): each per-node `agent` makes an OUTBOUND, bearer-authed POST to
//! `/ingest`. The server NEVER reaches into a TDX node — there is no fan-out, no SSRF surface, and no
//! node credential here. It stores the latest report per `node_id` in memory and serves them
//! read-only at `/api/attestation`. `/ingest` fails CLOSED when no token is configured.
//!
//! Following phases (to SECURITY.md): dcap-qvl quote verification + on-chain `is_measurements_approved`
//! cross-check; the askama public HTML page; and a SEPARATE, authed (CF Access), READ-ONLY `/admin`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use attestation_shared::NodeReport;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

struct Config {
    bind: String,
    /// Bearer token required on `/ingest`. None → ingest disabled (fail closed).
    ingest_token: Option<String>,
}

#[derive(Clone, Serialize)]
struct StoredReport {
    /// Unix seconds the portal received this push.
    received_at: u64,
    report: NodeReport,
}

struct AppState {
    cfg: Config,
    /// Latest report per node_id. Short-held std Mutex (no await while locked).
    reports: Mutex<HashMap<String, StoredReport>>,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config {
        bind: env_or("SERVER_BIND", "127.0.0.1:8088"),
        ingest_token: std::env::var("INGEST_TOKEN").ok().filter(|s| !s.is_empty()),
    };
    if cfg.ingest_token.is_none() {
        tracing::warn!("INGEST_TOKEN unset — /ingest is DISABLED (fail closed). Set it to accept agent pushes.");
    }
    tracing::info!(bind = %cfg.bind, ingest = cfg.ingest_token.is_some(), "starting attestation-portal server");

    let state = Arc::new(AppState {
        cfg,
        reports: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        // 256 KiB is ample for a node report; bound it so an unauth body can't grow memory.
        .route("/ingest", post(ingest).layer(DefaultBodyLimit::max(256 * 1024)))
        .route("/api/attestation", get(api_attestation))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&state.cfg.bind)
        .await
        .with_context(|| format!("bind {}", state.cfg.bind))?;
    tracing::info!("listening on {}", state.cfg.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Agent → portal push. Bearer-authed; fails closed if no token configured. Body bounded above.
async fn ingest(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let Some(expected) = state.cfg.ingest_token.as_deref() else {
        return StatusCode::SERVICE_UNAVAILABLE; // fail closed: no token configured
    };
    if !bearer_ok(&headers, expected) {
        return StatusCode::UNAUTHORIZED;
    }
    let report: NodeReport = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("ingest: bad body: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };
    let node_id = report.node_id.clone();
    let stored = StoredReport {
        received_at: now_secs(),
        report,
    };
    if let Ok(mut map) = state.reports.lock() {
        map.insert(node_id.clone(), stored);
    }
    tracing::info!(node = %node_id, "ingested report");
    StatusCode::OK
}

/// Public, read-only: the latest stored report per node.
async fn api_attestation(State(state): State<Arc<AppState>>) -> Json<Vec<StoredReport>> {
    let reports = match state.reports.lock() {
        Ok(map) => {
            let mut v: Vec<StoredReport> = map.values().cloned().collect();
            v.sort_by(|a, b| a.report.node_id.cmp(&b.report.node_id));
            v
        }
        Err(_) => Vec::new(),
    };
    Json(reports)
}

/// `Authorization: Bearer <token>` compared in constant time against the configured token.
fn bearer_ok(headers: &HeaderMap, expected: &str) -> bool {
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    else {
        return false;
    };
    ct_eq(token.as_bytes(), expected.as_bytes())
}

/// Constant-time byte compare (length is allowed to leak — tokens are fixed length).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
