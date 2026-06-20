//! Ops/dev tool: render the public attestation page to a standalone HTML file from REAL keystore
//! data, off the HTTP path — so a human can open it in a browser and review the sectioned layout
//! (decoded report + on-chain badge + compose section) before any deploy.
//!
//! It assembles a `CvmAttestation` from a node's live guest-agent `Info` (fetched out-of-band into a
//! small JSON bundle + the RA-TLS app_cert PEM), runs the SAME Phase-2 verify pipeline the server
//! runs (`verify::verify_report` — live Intel PCS + NEAR RPC), and renders through the SAME entry point
//! the live `/` handler uses (`page::render_index`). What you see in the file is exactly what a
//! visitor would see for this CVM.
//!
//! Inputs (paths overridable via env; sensible /tmp defaults):
//!   KS_DATA   JSON bundle of the real fields                 (default /tmp/ks_real_data.json)
//!   CERT_PEM  the RA-TLS app_cert PEM chain                  (default /tmp/keystore_app_cert.pem)
//!   OUT       output HTML path                               (default /tmp/attestation-preview.html)
//!
//! The bundle JSON (snake_case) carries: app_id, app_name, instance_id, device_id, os_image_hash,
//! mr_aggregated, compose_hash, key_provider, app_compose, and the 5 measurements
//! (mrtd/rtmr0..3). This is a dev/ops harness, so it panics on bad input (unlike the server request
//! path, which is strictly fail-closed and never panics).
//!
//! Run:
//!   cargo run -p attestation-server --example render_preview

use attestation_server::page::{self, StoredNode};
use attestation_server::verify;
use attestation_shared::{CvmAttestation, Measurements, NodeReport, Role};
use serde::Deserialize;

/// The real fields fetched from the keystore CVM's guest-agent `Info` (+ its `tcb_info`).
#[derive(Deserialize)]
struct RealData {
    app_id: String,
    #[allow(dead_code)]
    app_name: String,
    instance_id: String,
    device_id: String,
    os_image_hash: String,
    mr_aggregated: String,
    compose_hash: String,
    key_provider: Option<String>,
    /// dstack OS image tag (`vm_config.image`), e.g. `dstack-0.5.11`. Optional in the bundle.
    #[serde(default)]
    os_version: Option<String>,
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    app_compose: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let data_path = env_or("KS_DATA", "/tmp/ks_real_data.json");
    let cert_path = env_or("CERT_PEM", "/tmp/keystore_app_cert.pem");
    let out_path = env_or("OUT", "/tmp/attestation-preview.html");

    let data_json = std::fs::read_to_string(&data_path)
        .unwrap_or_else(|e| panic!("read {data_path}: {e}"));
    let d: RealData =
        serde_json::from_str(&data_json).unwrap_or_else(|e| panic!("parse {data_path}: {e}"));
    let app_cert_pem = std::fs::read_to_string(&cert_path)
        .unwrap_or_else(|e| panic!("read {cert_path}: {e}"));

    // Build the CVM exactly as the agent would normalize it for a testnet keystore.
    let cvm = CvmAttestation {
        vm_id: "vm-keystore-testnet".to_string(),
        name: "testnet-keystore".to_string(),
        role: Role::Keystore,
        network: Some("testnet".to_string()),
        status: "running".to_string(),
        uptime: None,
        app_id: d.app_id,
        instance_id: Some(d.instance_id),
        compose_hash: Some(d.compose_hash),
        device_id: Some(d.device_id),
        mr_aggregated: Some(d.mr_aggregated),
        os_image_hash: Some(d.os_image_hash),
        os_version: d.os_version,
        measurements: Some(Measurements {
            mrtd: d.mrtd,
            rtmr0: d.rtmr0,
            rtmr1: d.rtmr1,
            rtmr2: d.rtmr2,
            rtmr3: d.rtmr3,
        }),
        image_digests: Vec::new(),
        app_compose: Some(d.app_compose),
        key_provider: d.key_provider,
        app_cert_pem: Some(app_cert_pem),
        event_log: Vec::new(),
        error: None,
    };

    let report = NodeReport {
        node_id: "node-tdx-dal-2".to_string(),
        collected_at: now_secs(),
        cvms: vec![cvm],
    };

    // Run the real verify pipeline (live Intel PCS + NEAR RPC) to fill decoded + on-chain verdict.
    eprintln!("verifying (live Intel PCS + NEAR RPC)…");
    let verdicts = verify::verify_report(&report).await;
    if let Some(v) = verdicts.first() {
        eprintln!(
            "verdict: sig_valid={} tcb_status={:?} measurements_match={:?} on_chain_approved={:?} fmspc={:?} error={:?}",
            v.sig_valid, v.tcb_status, v.quote_measurements_match, v.on_chain_approved, v.fmspc, v.error
        );
    }

    // Render through the SAME entry point the live `/` handler uses.
    let now = now_secs();
    let nodes = [StoredNode {
        received_at: now,
        report: &report,
        verdicts: &verdicts,
    }];
    let html = page::render_index(now, &nodes).unwrap_or_else(|e| panic!("render: {e}"));

    std::fs::write(&out_path, &html).unwrap_or_else(|e| panic!("write {out_path}: {e}"));
    eprintln!("wrote {out_path} ({} bytes)", html.len());
}
