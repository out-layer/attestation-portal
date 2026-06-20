//! attestation-portal server — central aggregator (+ later: verifier, public page, /admin).
//!
//! v1 foundation (this file): fans out to each per-node `agent` and serves the aggregated read-only
//! attestation reports as JSON. SECURITY (see ../SECURITY.md):
//!   - the node list is **operator config only** (the `NODES` env var) — it is NEVER request-derived,
//!     so a request cannot make the server fetch an arbitrary URL (no SSRF).
//!   - strict connect/overall timeouts; one node failing is non-fatal (its slot carries an error).
//!   - read-only, anonymous, no secrets in responses.
//!
//! Following phases (built deliberately, to SECURITY.md): dcap-qvl quote verification + on-chain
//! `is_measurements_approved` cross-check; the askama public HTML page; and a SEPARATE, authenticated,
//! READ-ONLY `/admin` (not internet-exposed) — kept out of this binary's public surface.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use attestation_shared::NodeReport;
use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

struct Config {
    /// Operator-configured agent endpoints. NEVER request-derived (no SSRF).
    nodes: Vec<NodeEndpoint>,
    bind: String,
}

#[derive(Clone)]
struct NodeEndpoint {
    /// Operator label (display only).
    id: String,
    /// Base URL of that node's agent (e.g. `http://10.0.0.2:9300`).
    url: String,
}

struct AppState {
    cfg: Config,
    http: reqwest::Client,
}

/// One node's slot in the aggregated response: either its report or a non-fatal error.
#[derive(Serialize)]
struct NodeResult {
    node: String,
    url: String,
    report: Option<NodeReport>,
    error: Option<String>,
}

/// Parse `NODES="a=http://h1:9300, b=http://h2:9300"` (or bare `http://h:9300,...`).
fn parse_nodes(raw: &str) -> Vec<NodeEndpoint> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((id, url)) => NodeEndpoint {
                id: id.trim().to_string(),
                url: url.trim().trim_end_matches('/').to_string(),
            },
            None => NodeEndpoint {
                id: entry.to_string(),
                url: entry.trim_end_matches('/').to_string(),
            },
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let nodes = parse_nodes(&std::env::var("NODES").unwrap_or_default());
    if nodes.is_empty() {
        tracing::warn!(
            "NODES is empty — set NODES=\"node-a=http://10.0.0.2:9300,...\" (operator config; never request-derived)"
        );
    }
    let cfg = Config {
        nodes,
        bind: std::env::var("SERVER_BIND").unwrap_or_else(|_| "127.0.0.1:8088".into()),
    };
    tracing::info!(bind = %cfg.bind, nodes = cfg.nodes.len(), "starting attestation-portal server");

    let state = Arc::new(AppState {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(4))
            .user_agent("attestation-portal-server")
            .build()?,
        cfg,
    });

    let app = Router::new()
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

/// Public, read-only: the aggregated attestation of every configured node.
async fn api_attestation(State(state): State<Arc<AppState>>) -> Json<Vec<NodeResult>> {
    Json(collect_all(&state).await)
}

async fn collect_all(state: &AppState) -> Vec<NodeResult> {
    futures::future::join_all(state.cfg.nodes.iter().map(|n| fetch_node(state, n))).await
}

async fn fetch_node(state: &AppState, n: &NodeEndpoint) -> NodeResult {
    let url = format!("{}/attestation", n.url);
    let mk = |report, error| NodeResult {
        node: n.id.clone(),
        url: n.url.clone(),
        report,
        error,
    };
    match state.http.get(&url).send().await.and_then(|r| r.error_for_status()) {
        Ok(resp) => match resp.json::<NodeReport>().await {
            Ok(report) => mk(Some(report), None),
            Err(e) => mk(None, Some(format!("decode: {e}"))),
        },
        Err(e) => mk(None, Some(format!("fetch: {e}"))),
    }
}
