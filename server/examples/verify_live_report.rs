//! Ops/dev tool: run the verify pipeline on CVMs of a node report as the portal serves it
//! (`/api/attestation`), off the HTTP path. Prints each matching CVM's verdict as JSON.
//!
//! Env:
//!   REPORT_JSON  path to a saved `/api/attestation` answer   (required)
//!   APP_ID       only CVMs whose app_id starts with this      (optional)
//!
//!   curl -s https://workers.outlayer.ai/api/attestation -o /tmp/att.json
//!   REPORT_JSON=/tmp/att.json APP_ID=705dfe64 cargo run -p attestation-server --example verify_live_report
use attestation_server::verify::verify_cvm;
use attestation_shared::CvmAttestation;

#[tokio::main]
async fn main() {
    let path = std::env::var("REPORT_JSON").expect("REPORT_JSON");
    let want = std::env::var("APP_ID").unwrap_or_default();
    let d: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let nodes = d.as_array().cloned().unwrap_or_else(|| d["nodes"].as_array().cloned().unwrap_or_default());
    for n in nodes {
        let r = if n.get("report").is_some() { n["report"].clone() } else { n };
        for c in r["cvms"].as_array().cloned().unwrap_or_default() {
            let cvm: CvmAttestation = serde_json::from_value(c).unwrap();
            if !cvm.app_id.starts_with(&want) {
                continue;
            }
            let v = verify_cvm(&cvm).await;
            println!("{} {}: sig_valid={} tcb={:?} measurements_match={:?} on_chain_approved={:?} contract={:?} error={:?}",
                r["node_id"], cvm.name, v.sig_valid, v.tcb_status, v.quote_measurements_match, v.on_chain_approved, v.on_chain_contract, v.error);
        }
    }
}
