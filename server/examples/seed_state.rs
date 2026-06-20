//! Ops/dev tool: seed the server's STATE_FILE with the LIVE fleet so the real server (not a static
//! HTML file) can be viewed on localhost.
//!
//! It reads the guest-agent `Info` JSON bundles fetched out-of-band from the node (one file per CVM,
//! the raw `prpc/Info?json` response — keystore/worker/kms/gateway), normalizes each into a
//! `CvmAttestation` exactly as the agent would, assembles them into one `NodeReport`, runs the SAME
//! Phase-2 verify pipeline the server runs (`verify::verify_report` — live Intel PCS + NEAR RPC), and
//! writes the server's STATE_FILE JSON in the shape `load_state` expects:
//!
//!   { "<node_id>": { "received_at": <u64>, "report": <NodeReport>, "verdicts": [<CvmVerdict>] } }
//!
//! A per-CVM fetch/verify failure does NOT abort the seed — that CVM is included with whatever it
//! produced (the verdict carries the error fail-closed), and the rest still seed.
//!
//! This is a dev/ops harness, so it panics on bad input (unlike the server request path, which is
//! strictly fail-closed and never panics).
//!
//! Inputs (env-overridable; /tmp defaults):
//!   INFO_KEYSTORE   /tmp/info_keystore.json   (port ~9210)
//!   INFO_WORKER     /tmp/info_worker.json     (port ~9212)
//!   INFO_KMS        /tmp/info_kms.json        (port ~11005)
//!   INFO_GATEWAY    /tmp/info_gateway.json    (port ~9206)
//!   NODE_ID         node-tdx-dal-2
//!   OUT             /tmp/attestation-state.json
//!
//! Run:
//!   cargo run -p attestation-server --example seed_state

use attestation_server::verify;
use attestation_shared::{
    network_from_name, CvmAttestation, Measurements, NodeReport, Role,
};
use serde::Deserialize;

/// The guest-agent `Info` shape (only the fields we consume), mirroring the agent's `AppInfo`.
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
    device_id: Option<String>,
    #[serde(default)]
    mr_aggregated: Option<String>,
    #[serde(default)]
    os_image_hash: Option<String>,
    #[serde(default)]
    key_provider_info: Option<String>,
    #[serde(default)]
    compose_hash: Option<String>,
    #[serde(default)]
    vm_config: Option<String>,
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
    app_compose: Option<String>,
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

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|x| !x.is_empty())
}

/// `key_provider_info` is a JSON string `{"name":"kms",…}`; return the `name`.
fn parse_key_provider(s: Option<&str>) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(s?).ok()?;
    v.get("name").and_then(|n| n.as_str()).map(str::to_string)
}

/// `vm_config` JSON string carries the dstack OS image tag under `image` (e.g. `dstack-0.5.11`).
fn parse_os_version(s: Option<&str>) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(s?).ok()?;
    v.get("image")
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Pull unique `repo@sha256:<64hex>` image refs out of the measured compose blob (no regex dep —
/// simple scan), mirroring the agent's `extract_digests`.
fn extract_digests(compose: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in compose.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        if let Some((_, rest)) = tok.split_once("@sha256:") {
            let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() == 64 {
                let prefix = &tok[..tok.len() - rest.len()];
                let r = format!("{prefix}{}", &rest[..hex.len()]);
                if !out.contains(&r) {
                    out.push(r);
                }
            }
        }
    }
    out
}

/// Build a `CvmAttestation` from one guest-agent `Info` bundle, classifying role/network from `name`.
fn cvm_from_info(vm_id: &str, name: &str, info: &AppInfo) -> CvmAttestation {
    let role = Role::from_name(name);
    let network = network_from_name(name);

    let mut cvm = CvmAttestation {
        vm_id: vm_id.to_string(),
        name: name.to_string(),
        role,
        network,
        status: "running".to_string(),
        uptime: None,
        app_id: info.app_id.clone(),
        instance_id: non_empty(info.instance_id.clone()),
        compose_hash: info.compose_hash.clone(),
        device_id: info.device_id.clone(),
        mr_aggregated: info.mr_aggregated.clone(),
        os_image_hash: info.os_image_hash.clone(),
        os_version: parse_os_version(info.vm_config.as_deref()),
        measurements: None,
        image_digests: Vec::new(),
        app_compose: None,
        key_provider: parse_key_provider(info.key_provider_info.as_deref()),
        app_cert_pem: info.app_cert.clone(),
        event_log: Vec::new(),
        error: None,
    };

    match serde_json::from_str::<TcbInfoRaw>(&info.tcb_info) {
        Ok(tcb) => {
            cvm.measurements = Some(Measurements {
                mrtd: tcb.mrtd,
                rtmr0: tcb.rtmr0,
                rtmr1: tcb.rtmr1,
                rtmr2: tcb.rtmr2,
                rtmr3: tcb.rtmr3,
            });
            if let Some(compose) = tcb.app_compose.as_deref() {
                cvm.image_digests = extract_digests(compose);
            }
            cvm.app_compose = tcb.app_compose;
        }
        Err(e) => cvm.error = Some(format!("parse tcb_info: {e}")),
    }
    cvm
}

/// Load + parse one `Info` bundle file; on read/parse failure, return a placeholder CVM carrying the
/// error so the seed still includes it (don't abort the whole run for one missing file).
fn load_cvm(path: &str, vm_id: &str, name: &str) -> CvmAttestation {
    match std::fs::read_to_string(path) {
        Ok(s) => match serde_json::from_str::<AppInfo>(&s) {
            Ok(info) => cvm_from_info(vm_id, name, &info),
            Err(e) => placeholder(vm_id, name, format!("parse {path}: {e}")),
        },
        Err(e) => placeholder(vm_id, name, format!("read {path}: {e}")),
    }
}

fn placeholder(vm_id: &str, name: &str, err: String) -> CvmAttestation {
    eprintln!("WARN dropping live data for {name}: {err}");
    CvmAttestation {
        vm_id: vm_id.to_string(),
        name: name.to_string(),
        role: Role::from_name(name),
        network: network_from_name(name),
        status: "unknown".to_string(),
        uptime: None,
        app_id: String::new(),
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
        error: Some(err),
    }
}

#[tokio::main]
async fn main() {
    let node_id = env_or("NODE_ID", "node-tdx-dal-2");
    let out = env_or("OUT", "/tmp/attestation-state.json");

    // (file env-var, real vm_id, real vm name) for the four fleet CVMs.
    let specs = [
        (
            env_or("INFO_KEYSTORE", "/tmp/info_keystore.json"),
            "55112298-e7e7-47f4-9f75-bb673a686e2e",
            "testnet-keystore-0135-2",
        ),
        (
            env_or("INFO_WORKER", "/tmp/info_worker.json"),
            "ba0fdaca-c43c-4d4f-ac81-69acec833274",
            "testnet-worker-0135-6",
        ),
        (
            env_or("INFO_KMS", "/tmp/info_kms.json"),
            "36b47e71-b446-4ec4-923c-63cd01e2a0fb",
            "kms",
        ),
        (
            env_or("INFO_GATEWAY", "/tmp/info_gateway.json"),
            "0c6451de-22e6-49ca-a731-73f4e84dce96",
            "dstack-gateway",
        ),
    ];

    let cvms: Vec<CvmAttestation> = specs
        .iter()
        .map(|(path, vm_id, name)| load_cvm(path, vm_id, name))
        .collect();

    let report = NodeReport {
        node_id: node_id.clone(),
        collected_at: now_secs(),
        cvms,
    };

    eprintln!("verifying {} CVMs (live Intel PCS + NEAR RPC)…", report.cvms.len());
    let verdicts = verify::verify_report(&report).await;

    for v in &verdicts {
        eprintln!(
            "  {} sig_valid={} tcb={:?} q_match={:?} on_chain={:?} fmspc={:?}{}",
            v.vm_id,
            v.sig_valid,
            v.tcb_status,
            v.quote_measurements_match,
            v.on_chain_approved,
            v.fmspc,
            v.error.as_deref().map(|e| format!(" error={e}")).unwrap_or_default(),
        );
    }

    // Hand-build the STATE_FILE map exactly in the shape `main.rs::load_state`
    // (HashMap<String, StoredReport>) deserializes: { node_id: { received_at, report, verdicts } }.
    let received_at = now_secs();
    let state = serde_json::json!({
        node_id: {
            "received_at": received_at,
            "report": report,
            "verdicts": verdicts,
        }
    });

    let bytes = serde_json::to_vec_pretty(&state).expect("serialize state");
    std::fs::write(&out, &bytes).unwrap_or_else(|e| panic!("write {out}: {e}"));
    eprintln!("wrote {out} ({} bytes; {} CVMs)", bytes.len(), report.cvms.len());
}
