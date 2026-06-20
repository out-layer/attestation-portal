//! attestation-agent — per-node, read-only attestation collector for the OutLayer TDX fleet.
//!
//! Runs ON a TDX host as the vmm-owning user (so it can read `/proc/<pid>/cmdline` of the qemu CVMs
//! to discover their loopback guest-agent ports — the dstack vmm reassigns those on every CVM
//! stop/start, so they must be discovered, not hard-coded). It collects the VM list + each CVM's
//! guest-agent `Info`, normalizes it into a `NodeReport`, and **pushes it OUTBOUND** to the central
//! portal's `/ingest` endpoint.
//!
//! SECURITY (../SECURITY.md): the node only ever makes OUTBOUND connections — the central portal
//! never reaches INTO the TDX host, so a portal compromise yields no path/credential to this
//! crown-jewel host. The agent holds no secrets beyond a low-stakes push token (the data it pushes is
//! public; a leaked token at worst lets someone push fake reports, which on-chain/quote verification
//! detects). It performs NO control actions. A loopback-only `/attestation` + `/healthz` server is
//! kept for on-node debugging.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use attestation_shared::{CvmAttestation, EventLogEntry, Measurements, NodeReport, Role};
use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use regex::Regex;
use serde::Deserialize;

struct Config {
    vmm_rpc: String,
    /// Loopback debug server bind (NEVER 0.0.0.0).
    bind: String,
    node_id: String,
    /// Portal `/ingest` URL to push to. None → push disabled (debug server only).
    portal_url: Option<String>,
    /// Bearer token for `/ingest` (low-stakes; data is public).
    push_token: Option<String>,
    push_interval: u64,
}

struct AppState {
    cfg: Config,
    http: reqwest::Client,
    /// Matches a qemu user-net hostfwd for the guest-agent: `127.0.0.1:<port>-:8090`.
    port_re: Regex,
    /// Matches a docker image digest ref: `repo@sha256:<64 hex>`.
    image_re: Regex,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config {
        vmm_rpc: env_or("VMM_RPC", "http://127.0.0.1:11000"),
        bind: env_or("AGENT_BIND", "127.0.0.1:9300"),
        node_id: env_or("NODE_ID", &hostname()),
        portal_url: std::env::var("PORTAL_INGEST_URL").ok().filter(|s| !s.is_empty()),
        push_token: std::env::var("PUSH_TOKEN").ok().filter(|s| !s.is_empty()),
        push_interval: env_or("PUSH_INTERVAL_SECS", "30").parse().unwrap_or(30),
    };
    tracing::info!(
        vmm_rpc = %cfg.vmm_rpc, bind = %cfg.bind, node_id = %cfg.node_id,
        push = cfg.portal_url.is_some(), interval = cfg.push_interval,
        "starting attestation-agent"
    );

    let state = Arc::new(AppState {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        port_re: Regex::new(r"127\.0\.0\.1:(\d+)-:8090").unwrap(),
        image_re: Regex::new(r"([a-zA-Z0-9][a-zA-Z0-9._/-]*@sha256:[a-f0-9]{64})").unwrap(),
        cfg,
    });

    // Outbound push loop (the production data path). The node only ever connects OUT.
    if state.cfg.portal_url.is_some() {
        let st = state.clone();
        tokio::spawn(async move { push_loop(st).await });
    } else {
        tracing::warn!("PORTAL_INGEST_URL unset — push disabled (loopback debug server only)");
    }

    // Loopback-only debug server.
    let app = Router::new()
        .route("/attestation", get(attestation))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(&state.cfg.bind)
        .await
        .with_context(|| format!("bind {}", state.cfg.bind))?;
    tracing::info!("debug server on {}", state.cfg.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Periodically collect + push the node report OUTBOUND to the portal.
async fn push_loop(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(state.cfg.push_interval));
    loop {
        ticker.tick().await;
        match collect(&state).await {
            Ok(report) => match push_once(&state, &report).await {
                Ok(()) => tracing::info!(cvms = report.cvms.len(), "pushed attestation to portal"),
                Err(e) => tracing::warn!("push failed: {e:#}"),
            },
            Err(e) => tracing::warn!("collect failed: {e:#}"),
        }
    }
}

async fn push_once(state: &AppState, report: &NodeReport) -> Result<()> {
    let url = state.cfg.portal_url.as_deref().context("no portal url")?;
    let mut req = state.http.post(url).json(report);
    if let Some(token) = &state.cfg.push_token {
        req = req.bearer_auth(token);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

async fn attestation(State(state): State<Arc<AppState>>) -> Result<Json<NodeReport>, AppError> {
    Ok(Json(collect(&state).await?))
}

async fn collect(state: &AppState) -> Result<NodeReport> {
    let status: VmmStatus = prpc(&state.http, &format!("{}/prpc/Status?json", state.cfg.vmm_rpc))
        .await
        .context("vmm Status")?;
    let mut cvms = Vec::with_capacity(status.vms.len());
    for vm in &status.vms {
        cvms.push(collect_vm(state, vm).await);
    }
    Ok(NodeReport {
        node_id: state.cfg.node_id.clone(),
        collected_at: now_secs(),
        cvms,
    })
}

async fn collect_vm(state: &AppState, vm: &VmStatus) -> CvmAttestation {
    let mut cvm = CvmAttestation {
        vm_id: vm.id.clone(),
        name: vm.name.clone(),
        role: Role::from_name(&vm.name),
        status: vm.status.clone(),
        uptime: vm.uptime.clone(),
        app_id: vm.app_id.clone(),
        instance_id: non_empty(vm.instance_id.clone()),
        compose_hash: None,
        device_id: None,
        mr_aggregated: None,
        os_image_hash: None,
        measurements: None,
        image_digests: Vec::new(),
        key_provider: None,
        app_cert_pem: None,
        event_log: Vec::new(),
        error: None,
    };

    if vm.status != "running" {
        cvm.error = Some(format!("vm status is '{}'", vm.status));
        return cvm;
    }
    let port = match find_agent_port(&vm.id, &state.port_re) {
        Some(p) => p,
        None => {
            cvm.error = Some("guest-agent port not found (no live qemu hostfwd :8090)".into());
            return cvm;
        }
    };
    match fetch_info(state, port).await {
        Ok(info) => apply_info(&mut cvm, state, info),
        Err(e) => cvm.error = Some(format!("Info fetch failed on :{port}: {e:#}")),
    }
    cvm
}

fn apply_info(cvm: &mut CvmAttestation, state: &AppState, info: AppInfo) {
    cvm.compose_hash = info.compose_hash;
    cvm.device_id = info.device_id;
    cvm.mr_aggregated = info.mr_aggregated;
    cvm.os_image_hash = info.os_image_hash;
    cvm.app_cert_pem = info.app_cert;
    cvm.key_provider = parse_key_provider(info.key_provider_info.as_deref());

    match serde_json::from_str::<TcbInfoRaw>(&info.tcb_info) {
        Ok(tcb) => {
            cvm.measurements = Some(Measurements {
                mrtd: tcb.mrtd,
                rtmr0: tcb.rtmr0,
                rtmr1: tcb.rtmr1,
                rtmr2: tcb.rtmr2,
                rtmr3: tcb.rtmr3,
            });
            cvm.event_log = tcb
                .event_log
                .into_iter()
                .map(|e| EventLogEntry {
                    imr: e.imr,
                    event_type: e.event_type,
                    digest: e.digest,
                    event: e.event,
                    event_payload: e.event_payload,
                })
                .collect();
            if let Some(compose) = tcb.app_compose.as_deref() {
                cvm.image_digests = extract_digests(compose, &state.image_re);
            }
        }
        Err(e) => cvm.error = Some(format!("parse tcb_info: {e}")),
    }
}

async fn fetch_info(state: &AppState, port: u16) -> Result<AppInfo> {
    prpc(&state.http, &format!("http://127.0.0.1:{port}/prpc/Info?json")).await
}

/// dstack prpc call: `POST <url>` with a `{}` body returns JSON when the path carries `?json`.
async fn prpc<T: serde::de::DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T> {
    let resp = http
        .post(url)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json::<T>().await?)
}

/// Discover a CVM's guest-agent host port by scanning the live qemu processes for the one whose
/// cmdline contains this vm uuid, then extracting its `127.0.0.1:<port>-:8090` hostfwd. Mirrors
/// `deploy/self-hosted-tdx/worker-ctl.sh:agent_port()`.
fn find_agent_port(vm_id: &str, re: &Regex) -> Option<u16> {
    let dir = std::fs::read_dir("/proc").ok()?;
    for entry in dir.flatten() {
        let fname = entry.file_name();
        let name = fname.to_str().unwrap_or("");
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let raw = match std::fs::read(format!("/proc/{name}/cmdline")) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let cmd = String::from_utf8_lossy(&raw).replace('\0', " ");
        if !cmd.contains("qemu-system") || !cmd.contains(vm_id) {
            continue;
        }
        if let Some(p) = re
            .captures(&cmd)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u16>().ok())
        {
            return Some(p);
        }
    }
    None
}

/// Pull unique `repo@sha256:…` image refs out of the measured app-compose blob.
fn extract_digests(compose: &str, re: &Regex) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in re.captures_iter(compose) {
        let img = c.get(1).unwrap().as_str().to_string();
        if !out.contains(&img) {
            out.push(img);
        }
    }
    out
}

/// `key_provider_info` is a JSON string `{"name":"kms","id":"…"}`; return the `name`.
fn parse_key_provider(s: Option<&str>) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(s?).ok()?;
    v.get("name").and_then(|n| n.as_str()).map(str::to_string)
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|x| !x.is_empty())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "node".into())
}

/// Wrap anyhow errors so the loopback debug handler can `?` and return 500 with a logged cause.
struct AppError(anyhow::Error);
impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError(e)
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("request error: {:#}", self.0);
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("error: {}", self.0),
        )
            .into_response()
    }
}

// ---- dstack vmm + guest-agent wire types (only the fields we use) ----

#[derive(Deserialize)]
struct VmmStatus {
    #[serde(default)]
    vms: Vec<VmStatus>,
}

#[derive(Deserialize)]
struct VmStatus {
    id: String,
    name: String,
    status: String,
    #[serde(default)]
    uptime: Option<String>,
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    instance_id: Option<String>,
}

#[allow(dead_code)] // some fields kept to document the `Info` shape even if unused today
#[derive(Deserialize)]
struct AppInfo {
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    instance_id: Option<String>,
    #[serde(default)]
    app_cert: Option<String>,
    #[serde(default)]
    tcb_info: String,
    #[serde(default)]
    app_name: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    mr_aggregated: Option<String>,
    #[serde(default)]
    os_image_hash: Option<String>,
    #[serde(default)]
    key_provider_info: Option<String>,
    #[serde(default)]
    compose_hash: Option<String>,
}

#[derive(Deserialize)]
struct TcbInfoRaw {
    #[serde(default)]
    mrtd: String,
    #[serde(default)]
    rtmr0: String,
    #[serde(default)]
    rtmr1: String,
    #[serde(default)]
    rtmr2: String,
    #[serde(default)]
    rtmr3: String,
    #[serde(default)]
    event_log: Vec<EventLogRaw>,
    #[serde(default)]
    app_compose: Option<String>,
}

#[derive(Deserialize)]
struct EventLogRaw {
    #[serde(default)]
    imr: u32,
    #[serde(default)]
    event_type: u64,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    event_payload: Option<String>,
}
