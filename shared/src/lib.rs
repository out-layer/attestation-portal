//! Wire types shared between the per-node `agent` and the central `server`.
//!
//! These mirror the normalized attestation snapshot a node agent produces from the dstack vmm
//! `Status` + each CVM's guest-agent `Info`. The server consumes `NodeReport` to verify quotes
//! (dcap-qvl) and cross-check measurements against the on-chain approved list.

use serde::{Deserialize, Serialize};

/// One TDX host's attestation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReport {
    /// Operator label for this server (e.g. `node-tdx-dal-2`).
    pub node_id: String,
    /// Unix seconds when the agent assembled this report.
    pub collected_at: u64,
    pub cvms: Vec<CvmAttestation>,
}

/// One CVM (kms / gateway / keystore / worker) on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvmAttestation {
    /// dstack vmm uuid.
    pub vm_id: String,
    /// vmm VM label (`kms`, `dstack-gateway`, `testnet-keystore-…`, `…-worker-…`).
    pub name: String,
    pub role: Role,
    /// `testnet` / `mainnet` derived from the VM name; `None` for net-agnostic CVMs (kms, gateway).
    /// The server uses it to pick the right on-chain contracts for the measurement cross-check.
    pub network: Option<String>,
    /// vmm status string (`running`, `exited`, …).
    pub status: String,
    pub uptime: Option<String>,
    /// `sha256(app-compose.json)[:40]` — the app identity (== `compose_hash[:40]`).
    pub app_id: String,
    pub instance_id: Option<String>,
    pub compose_hash: Option<String>,
    pub device_id: Option<String>,
    pub mr_aggregated: Option<String>,
    pub os_image_hash: Option<String>,
    /// dstack guest OS image tag, parsed from the guest-agent `Info.vm_config.image` (e.g.
    /// `dstack-0.5.11`) — the real, per-CVM dynamic OS version. `None` on older agents that don't
    /// forward it (the page then falls back to `os_image_hash` as the precise OS identity).
    pub os_version: Option<String>,
    /// The 5 TDX registers (96 hex chars each). Absent if the guest-agent was unreachable.
    pub measurements: Option<Measurements>,
    /// Docker image refs (`repo@sha256:…`) parsed from the measured app-compose.
    pub image_digests: Vec<String>,
    /// The raw app-compose JSON (`tcb_info.app_compose`): docker_compose_file, allowed_envs,
    /// pre_launch_script, features, gateway_enabled, kms_enabled. This is the measured source
    /// identity ("Compose File" in Phala's explorer). `None` until the agent is redeployed (older
    /// reports omit it). Rendered server-side, auto-escaped — never trusted as markup.
    pub app_compose: Option<String>,
    /// `kms` or `local-sgx`.
    pub key_provider: Option<String>,
    /// RA-TLS cert PEM; the TDX quote is embedded as an X.509 extension (the server extracts +
    /// dcap-qvl-verifies it). The guest-agent's host endpoint does not expose a raw `GetQuote`.
    pub app_cert_pem: Option<String>,
    pub event_log: Vec<EventLogEntry>,
    /// Non-fatal per-CVM collection error — the rest of the node report still renders.
    pub error: Option<String>,
}

/// The 5 TDX measurement registers (each a 48-byte SHA-384, hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurements {
    /// Virtual firmware (OVMF).
    pub mrtd: String,
    /// Virtual hardware config (vCPU/RAM/devices) — differs per CVM by sizing.
    pub rtmr0: String,
    /// Linux kernel.
    pub rtmr1: String,
    /// Kernel cmdline + initrd (incl. rootfs hash).
    pub rtmr2: String,
    /// dstack app identity: compose-hash, app-id, instance-id, key-provider.
    pub rtmr3: String,
}

/// One boot event that replays into RTMR3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    pub imr: u32,
    pub event_type: u64,
    pub digest: String,
    pub event: Option<String>,
    pub event_payload: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Kms,
    Gateway,
    Keystore,
    Worker,
    Unknown,
}

/// Derive `testnet` / `mainnet` from a VM label, or `None` for net-agnostic CVMs (kms, gateway).
pub fn network_from_name(name: &str) -> Option<String> {
    let n = name.to_ascii_lowercase();
    if n.contains("testnet") {
        Some("testnet".to_string())
    } else if n.contains("mainnet") {
        Some("mainnet".to_string())
    } else {
        None
    }
}

impl Role {
    /// Classify a CVM by its vmm VM label.
    pub fn from_name(name: &str) -> Role {
        let n = name.to_ascii_lowercase();
        if n.contains("kms") {
            Role::Kms
        } else if n.contains("gateway") {
            Role::Gateway
        } else if n.contains("keystore") {
            Role::Keystore
        } else if n.contains("worker") {
            Role::Worker
        } else {
            Role::Unknown
        }
    }
}
