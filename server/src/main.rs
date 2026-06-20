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
use attestation_shared::{NodeReport, Role};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
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
        // Stable per-network keystore links: resolve the CURRENT keystore CVM for that network from
        // stored reports and redirect to its `/app/<app_id>` detail page. Lets the dashboard link to
        // a fixed URL without knowing the (rotating) app_id. The network is bound per-route here, so
        // no path param is request-derived (no SSRF surface — `network` is a hard-coded literal).
        .route(
            "/testnet-keystore",
            get(|state: State<Arc<AppState>>| async move { keystore_redirect(state.0, "testnet") }),
        )
        .route(
            "/mainnet-keystore",
            get(|state: State<Arc<AppState>>| async move { keystore_redirect(state.0, "mainnet") }),
        )
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

/// Stable per-network keystore redirect (`GET /testnet-keystore` | `/mainnet-keystore`): resolve the
/// CURRENT keystore CVM for `network` from stored reports and 303-redirect to its `/app/<app_id>`
/// detail page (there is exactly one keystore per network). This gives the dashboard a fixed URL that
/// survives keystore redeploys (the `app_id` rotates with each compose change).
///
/// Lock discipline (matches the rest of the file): take the std Mutex only to find + CLONE the one
/// `app_id`, then release it — no await / heavy work while locked. Never panics on a wire value and
/// reads only already-public attestation data; a poisoned lock degrades to the friendly 404.
///
/// If no such keystore is currently reporting (e.g. the mainnet keystore isn't deployed yet) → a
/// small, auto-escaped HTML page (the not-found style) with `404 Not Found`, never a redirect to a
/// dead page and never a panic.
fn keystore_redirect(state: Arc<AppState>, network: &str) -> Response {
    let app_id = match state.reports.lock() {
        Ok(map) => find_keystore_app_id(map.values(), network),
        Err(_) => None, // poisoned lock → behave as "not found" (the page is still up)
    };

    match app_id {
        Some(app_id) if !app_id.is_empty() => {
            // Relative path; `Redirect::to` emits a 303 See Other to `/app/<app_id>`.
            Redirect::to(&format!("/app/{app_id}")).into_response()
        }
        // No keystore for this network (or a degraded report with an empty app_id) — friendly 404.
        _ => {
            let body = page::render_no_keystore(network).unwrap_or_else(|e| {
                tracing::error!("no-keystore render failed: {e}");
                "<!doctype html><title>OutLayer</title><p>no keystore is currently reporting. \
                 <a href=\"/\">back</a></p>"
                    .to_string()
            });
            (StatusCode::NOT_FOUND, Html(body)).into_response()
        }
    }
}

/// Find the `app_id` of the keystore CVM for `network` across all stored reports: the first CVM with
/// `role == Role::Keystore` and `network` matching (there is exactly one keystore per network). If
/// several match — which shouldn't happen — prefer the one from the most-recently-received report so
/// the link follows the freshest deployment. Pure + borrow-only; no IO, no panics.
fn find_keystore_app_id<'a>(
    reports: impl IntoIterator<Item = &'a StoredReport>,
    network: &str,
) -> Option<String> {
    reports
        .into_iter()
        .flat_map(|stored| {
            stored
                .report
                .cvms
                .iter()
                .filter(|c| c.role == Role::Keystore && c.network.as_deref() == Some(network))
                .map(move |c| (stored.received_at, c.app_id.clone()))
        })
        // Most-recently-received report wins if more than one keystore matches (shouldn't happen).
        .max_by_key(|(received_at, _)| *received_at)
        .map(|(_, app_id)| app_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_shared::CvmAttestation;

    /// Build a keystore CVM for `network` with the given `app_id`. Only the fields the keystore
    /// redirect lookup reads (`role`, `network`, `app_id`) matter; the rest are benign defaults.
    fn keystore_cvm(network: &str, app_id: &str) -> CvmAttestation {
        CvmAttestation {
            vm_id: format!("vm-{app_id}"),
            name: format!("{network}-keystore"),
            role: Role::Keystore,
            network: Some(network.to_string()),
            status: "running".to_string(),
            uptime: None,
            app_id: app_id.to_string(),
            instance_id: None,
            compose_hash: None,
            device_id: None,
            mr_aggregated: None,
            os_image_hash: None,
            os_version: None,
            measurements: None,
            image_digests: Vec::new(),
            app_compose: None,
            key_provider: None,
            app_cert_pem: None,
            event_log: Vec::new(),
            error: None,
        }
    }

    /// A non-keystore (worker) CVM that must NOT be picked up by the keystore lookup, even on the
    /// same network.
    fn worker_cvm(network: &str, app_id: &str) -> CvmAttestation {
        CvmAttestation {
            role: Role::Worker,
            name: format!("{network}-worker"),
            ..keystore_cvm(network, app_id)
        }
    }

    fn stored_report(received_at: u64, cvms: Vec<CvmAttestation>) -> StoredReport {
        StoredReport {
            received_at,
            report: NodeReport {
                node_id: format!("node-{received_at}"),
                collected_at: received_at,
                cvms,
            },
            verdicts: Vec::new(),
        }
    }

    /// Build an `AppState` carrying the given stored reports (keyed by node_id), no ingest token / no
    /// state file — enough to drive the read-only keystore redirect handler in-process.
    fn state_with(reports: Vec<StoredReport>) -> Arc<AppState> {
        let mut map: HashMap<String, StoredReport> = HashMap::new();
        for r in reports {
            map.insert(r.report.node_id.clone(), r);
        }
        Arc::new(AppState {
            cfg: Config { bind: "127.0.0.1:0".to_string(), ingest_token: None, state_file: None },
            reports: Mutex::new(map),
        })
    }

    /// A stored report whose keystore CVM is testnet → the testnet redirect lands on its `/app/...`.
    #[test]
    fn testnet_keystore_redirects_to_app_detail() {
        let state = state_with(vec![stored_report(10, vec![keystore_cvm("testnet", "abc123")])]);
        let resp = keystore_redirect(state, "testnet");

        // 303 See Other (axum `Redirect::to`), Location pointing at the keystore's detail page.
        assert!(
            resp.status().is_redirection(),
            "expected a 3xx redirect, got {}",
            resp.status()
        );
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("location header present");
        assert_eq!(location, "/app/abc123");
    }

    /// No testnet keystore reporting → 404 with the friendly body, never a panic, no Location.
    #[test]
    fn missing_testnet_keystore_yields_friendly_404() {
        // A worker on testnet + a keystore on the OTHER network — neither should match testnet.
        let state = state_with(vec![stored_report(
            10,
            vec![worker_cvm("testnet", "wkr1"), keystore_cvm("mainnet", "main1")],
        )]);
        let resp = keystore_redirect(state, "testnet");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            resp.headers().get(axum::http::header::LOCATION).is_none(),
            "a 404 must not carry a redirect Location"
        );
    }

    /// Each network resolves its OWN keystore independently, even when both are reporting together.
    #[test]
    fn mainnet_and_testnet_resolve_independently() {
        let state = state_with(vec![stored_report(
            10,
            vec![keystore_cvm("testnet", "tnet1"), keystore_cvm("mainnet", "mnet1")],
        )]);

        let testnet = keystore_redirect(state.clone(), "testnet");
        assert_eq!(testnet.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            testnet.headers().get(axum::http::header::LOCATION).unwrap(),
            "/app/tnet1"
        );

        let mainnet = keystore_redirect(state, "mainnet");
        assert_eq!(mainnet.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            mainnet.headers().get(axum::http::header::LOCATION).unwrap(),
            "/app/mnet1"
        );
    }

    /// The pure lookup ignores non-keystore roles and wrong networks, and — should two keystores ever
    /// match — prefers the one from the most-recently-received report.
    #[test]
    fn find_keystore_app_id_filters_and_prefers_newest() {
        // A worker on testnet must be ignored even though it's the same network.
        let only_worker = [stored_report(10, vec![worker_cvm("testnet", "wkr")])];
        assert_eq!(find_keystore_app_id(only_worker.iter(), "testnet"), None);

        // Two testnet keystores (shouldn't happen) across two reports → newest received wins.
        let dup = [
            stored_report(10, vec![keystore_cvm("testnet", "old")]),
            stored_report(20, vec![keystore_cvm("testnet", "new")]),
        ];
        assert_eq!(
            find_keystore_app_id(dup.iter(), "testnet"),
            Some("new".to_string())
        );

        // A mainnet keystore does not satisfy a testnet lookup.
        let other_net = [stored_report(10, vec![keystore_cvm("mainnet", "m")])];
        assert_eq!(find_keystore_app_id(other_net.iter(), "testnet"), None);
    }
}
