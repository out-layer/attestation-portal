//! attestation-portal server — receives pushed node reports + serves them (+ later: verify, page).
//!
//! PUSH model (../SECURITY.md): each per-node `agent` makes an OUTBOUND, bearer-authed POST to
//! `/ingest`. The server NEVER reaches into a TDX node — no fan-out, no SSRF surface, no node
//! credential here. It keeps the latest report per `node_id` in memory and serves them read-only at
//! `/api/attestation`. `/ingest` fails CLOSED when no token is configured.
//!
//! Durability: the latest map is mirrored to a JSON file (`STATE_FILE`) on every ingest and loaded on
//! startup, so a server restart restores the last-known attestation immediately instead of showing a
//! blank page until agents re-push. (No DB — the data is small + self-refreshing; SQLite only if we
//! later want full history.)
//!
//! Phase 2 (this commit): after storing a pushed report, a background task runs dcap-qvl quote
//! verification + the on-chain `is_measurements_approved` cross-check (see `verify.rs`) and writes
//! the resulting per-CVM `verdicts` back into the stored entry. `/ingest` does NOT wait on it.
//!
//! Following phases (to SECURITY.md): the askama public HTML page.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use attestation_shared::NodeReport;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use attestation_server::page;
use attestation_server::verify::{self, CvmVerdict};

struct Config {
    bind: String,
    /// Bearer token required on `/ingest`. None → ingest disabled (fail closed).
    ingest_token: Option<String>,
    /// Path to persist the latest-report map (JSON). None → in-memory only.
    state_file: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredReport {
    /// Unix seconds the portal received this push (drives the "last seen live" freshness signal).
    received_at: u64,
    report: NodeReport,
    /// Per-CVM verification verdicts (dcap-qvl + on-chain), filled in by a background task shortly
    /// after ingest. Empty until that task completes (or if every CVM failed to produce a verdict).
    #[serde(default)]
    verdicts: Vec<CvmVerdict>,
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
        state_file: std::env::var("STATE_FILE").ok().filter(|s| !s.is_empty()),
    };
    if cfg.ingest_token.is_none() {
        tracing::warn!("INGEST_TOKEN unset — /ingest is DISABLED (fail closed). Set it to accept agent pushes.");
    }
    let initial = cfg.state_file.as_deref().map(load_state).unwrap_or_default();
    tracing::info!(
        bind = %cfg.bind, ingest = cfg.ingest_token.is_some(),
        state_file = cfg.state_file.is_some(), restored = initial.len(),
        "starting attestation-portal server"
    );

    let state = Arc::new(AppState {
        cfg,
        reports: Mutex::new(initial),
    });

    let app = Router::new()
        // Public, server-rendered HTML attestation LIST (Phase 3) — one compact row per CVM.
        .route("/", get(index))
        // Per-app DETAIL page: the full sectioned "verified aspects" view for one app_id.
        .route("/app/:app_id", get(app_detail))
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
    let received_at = now_secs();
    let stored = StoredReport {
        received_at,
        report: report.clone(),
        verdicts: Vec::new(), // filled asynchronously below; the page shows "verifying" until then
    };
    // Update the map and, if persisting, snapshot it WITHOUT holding the lock across file IO.
    let snapshot = match state.reports.lock() {
        Ok(mut map) => {
            map.insert(node_id.clone(), stored);
            state.cfg.state_file.as_ref().map(|_| map.clone())
        }
        Err(_) => None,
    };
    if let (Some(path), Some(snap)) = (state.cfg.state_file.as_deref(), snapshot) {
        save_state(path, &snap);
    }
    tracing::info!(node = %node_id, "ingested report");

    // Verify in the background so the agent's push returns immediately. The async verification does
    // network IO (PCCS + NEAR RPC) and must NOT run while holding the std Mutex; we take the lock
    // only briefly afterward to write the verdicts back — and only if the entry is still THIS report
    // (same node, not superseded by a newer push in the meantime). Compared by `received_at`.
    tokio::spawn(verify_in_background(state.clone(), report, received_at));

    StatusCode::OK
}

/// Background verification: run the verify pipeline off the request path, then merge the verdicts
/// into the stored entry iff it is still the same (or older) report we just ingested.
async fn verify_in_background(state: Arc<AppState>, report: NodeReport, received_at: u64) {
    let node_id = report.node_id.clone();
    let verdicts = verify::verify_report(&report).await;

    // Brief, no-await critical section: stamp the verdicts onto the current entry if unchanged.
    let snapshot = match state.reports.lock() {
        Ok(mut map) => {
            match map.get_mut(&node_id) {
                // Only write if the stored entry is the very report we verified. A newer push
                // (greater received_at) means our verdicts are stale — drop them.
                Some(entry) if entry.received_at == received_at => {
                    entry.verdicts = verdicts;
                    state.cfg.state_file.as_ref().map(|_| map.clone())
                }
                _ => None,
            }
        }
        Err(_) => None,
    };
    if let (Some(path), Some(snap)) = (state.cfg.state_file.as_deref(), snapshot) {
        save_state(path, &snap);
    }
    tracing::info!(node = %node_id, "verification complete");
}

/// Public, server-rendered HTML page: the latest attestation per node + the Phase 2 verdicts.
///
/// Lock discipline (matches the rest of the file): take the std Mutex only to CLONE the snapshot,
/// release it, then do all the view-model building + template rendering with the lock dropped — no
/// await and no heavy work while locked. The page is built entirely from already-stored public data,
/// so nothing here can panic on a wire value (no `unwrap`/`expect` on report fields).
async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    let snapshot = snapshot_reports(&state);

    let now = now_secs();
    let nodes = borrow_nodes(&snapshot);

    match page::render_index(now, &nodes) {
        Ok(html) => Html(html),
        Err(e) => {
            // A compiled template should not fail at runtime; if it somehow does, surface a minimal
            // page rather than panicking the request. No internal detail leaks to the visitor.
            tracing::error!("index render failed: {e}");
            Html("<!doctype html><title>OutLayer</title><p>temporarily unavailable</p>".to_string())
        }
    }
}

/// Per-app detail page (`GET /app/:app_id`): the full sectioned "verified aspects" view for EVERY CVM
/// instance whose `app_id` matches the path param. Same lock discipline as `index`: clone the
/// snapshot under the lock, render after dropping it. An unknown app_id → a friendly 404 (small HTML
/// body + link back to `/`), never a panic/500.
async fn app_detail(
    State(state): State<Arc<AppState>>,
    Path(app_id): Path<String>,
) -> (StatusCode, Html<String>) {
    let snapshot = snapshot_reports(&state);

    let now = now_secs();
    let nodes = borrow_nodes(&snapshot);

    match page::render_app(&app_id, now, &nodes) {
        // A matching app — full detail page, 200.
        Ok(Some(html)) => (StatusCode::OK, Html(html)),
        // No CVM carries this app_id — friendly 404 (the body itself is render-failure-tolerant).
        Ok(None) => {
            let body = page::render_unknown_app(&app_id).unwrap_or_else(|e| {
                tracing::error!("unknown-app render failed: {e}");
                "<!doctype html><title>OutLayer</title><p>unknown app id. <a href=\"/\">back</a></p>"
                    .to_string()
            });
            (StatusCode::NOT_FOUND, Html(body))
        }
        Err(e) => {
            tracing::error!("app detail render failed: {e}");
            (
                StatusCode::OK,
                Html("<!doctype html><title>OutLayer</title><p>temporarily unavailable</p>".to_string()),
            )
        }
    }
}

/// Take the std Mutex only to CLONE the stored reports (sorted by node_id for a stable page order),
/// then release it. A poisoned lock must not take the public page down — return empty. No await /
/// heavy work is done while the lock is held (the caller renders afterward).
fn snapshot_reports(state: &Arc<AppState>) -> Vec<StoredReport> {
    match state.reports.lock() {
        Ok(map) => {
            let mut v: Vec<StoredReport> = map.values().cloned().collect();
            v.sort_by(|a, b| a.report.node_id.cmp(&b.report.node_id));
            v
        }
        Err(_) => Vec::new(),
    }
}

/// Borrow a cloned snapshot into the `page::StoredNode` view the render fns consume.
fn borrow_nodes(snapshot: &[StoredReport]) -> Vec<page::StoredNode<'_>> {
    snapshot
        .iter()
        .map(|s| page::StoredNode {
            received_at: s.received_at,
            report: &s.report,
            verdicts: &s.verdicts,
        })
        .collect()
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

/// Load the persisted map on startup; missing/corrupt file → start empty (non-fatal).
fn load_state(path: &str) -> HashMap<String, StoredReport> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("state file {path} unreadable ({e}) — starting empty");
            HashMap::new()
        }),
        Err(_) => HashMap::new(),
    }
}

/// Atomically persist the map (write tmp + rename) so a crash mid-write can't corrupt it.
fn save_state(path: &str, map: &HashMap<String, StoredReport>) {
    let tmp = format!("{path}.tmp");
    let ok = serde_json::to_vec(map)
        .map_err(|e| anyhow::anyhow!("serialize: {e}"))
        .and_then(|bytes| std::fs::write(&tmp, bytes).map_err(Into::into))
        .and_then(|_| std::fs::rename(&tmp, path).map_err(Into::into));
    if let Err(e) = ok {
        tracing::warn!("failed to persist state to {path}: {e:#}");
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
