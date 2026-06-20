//! Ops/dev tool: run the Phase 2 verify pipeline against a single real CVM cert, off the HTTP path.
//!
//! Reads an app_cert PEM chain + the 5 reported measurements from env vars, builds a
//! `CvmAttestation`, and prints the resulting `CvmVerdict` as pretty JSON. Used to validate quote
//! extraction (OID `1.3.6.1.4.1.62397.1.8`) + dcap-qvl verification + the on-chain
//! `is_measurements_approved` cross-check against a live node's cert, without standing up the server.
//!
//! Env:
//!   CERT_PEM   path to the app_cert PEM chain file                       (required)
//!   MRTD, RTMR0, RTMR1, RTMR2, RTMR3   the 96-hex-char reported measurements (required)
//!   VM_NAME    VM label used to derive role + network (default "testnet-keystore")
//!
//! Example:
//!   CERT_PEM=/tmp/keystore_app_cert.pem MRTD=.. RTMR0=.. RTMR1=.. RTMR2=.. RTMR3=.. \
//!     cargo run -p attestation-server --example verify_one
//!
//! This is a dev/ops harness, so it panics on bad input (unlike the server request path, which is
//! strictly fail-closed and never panics).

use attestation_server::verify::verify_cvm;
use attestation_shared::{network_from_name, CvmAttestation, Measurements, Role};

fn env_req(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("missing required env var {key}"))
}

#[tokio::main]
async fn main() {
    let cert_path = env_req("CERT_PEM");
    let app_cert_pem =
        std::fs::read_to_string(&cert_path).unwrap_or_else(|e| panic!("read {cert_path}: {e}"));
    let name = std::env::var("VM_NAME").unwrap_or_else(|_| "testnet-keystore".to_string());
    let role = Role::from_name(&name);
    let network = network_from_name(&name);

    let measurements = Measurements {
        mrtd: env_req("MRTD"),
        rtmr0: env_req("RTMR0"),
        rtmr1: env_req("RTMR1"),
        rtmr2: env_req("RTMR2"),
        rtmr3: env_req("RTMR3"),
    };

    let cvm = CvmAttestation {
        vm_id: "example".to_string(),
        name,
        role,
        network,
        status: "running".to_string(),
        uptime: None,
        app_id: String::new(),
        instance_id: None,
        compose_hash: None,
        device_id: None,
        mr_aggregated: None,
        os_image_hash: None,
        os_version: None,
        measurements: Some(measurements),
        image_digests: Vec::new(),
        app_compose: None,
        key_provider: None,
        app_cert_pem: Some(app_cert_pem),
        event_log: Vec::new(),
        error: None,
    };

    let verdict = verify_cvm(&cvm).await;
    println!(
        "{}",
        serde_json::to_string_pretty(&verdict).expect("serialize verdict")
    );
}
