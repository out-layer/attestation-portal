//! Phase 2 — the verify pipeline. Turns a pushed `CvmAttestation` into a `CvmVerdict`.
//!
//! This is the whole point of the portal (../SECURITY.md): PROVE each CVM is a genuine TDX TEE
//! running the on-chain-approved code. So it is written FAIL CLOSED — every error path (bad PEM,
//! missing quote, PCS unreachable, dcap-qvl reject, RPC failure) yields a verdict with
//! `sig_valid = false` and a populated `error`, never a panic and never a silent "ok". No
//! `.unwrap()` / `.expect()` touches external or network data.
//!
//! For each CVM we:
//!   1. Extract the raw Intel TDX quote from the leaf RA-TLS cert (`app_cert_pem`).
//!   2. Fetch DCAP collateral directly from Intel's PCS for that quote.
//!   3. dcap-qvl `verify()` it (signature + TCB chain). Note: `verify()` returns `Err` only when
//!      the platform TCB is `Revoked`; it returns `Ok` for OutOfDate / ConfigurationNeeded too — so
//!      we record the actual TCB status string and treat ONLY `"UpToDate"` as fully good upstream.
//!   4. Compare the dcap-qvl-parsed measurements (mr_td / rt_mr0..3) against the report's claimed
//!      `measurements` — this binds the verified quote to the values the page renders.
//!   5. Cross-check against the chain, for worker/keystore CVMs on their network (net-agnostic
//!      CVMs — kms/gateway — skip this):
//!      - a worker: its five measurements on the register contract's list (`is_measurements_approved`);
//!      - a keystore: its build on the keystore DAO (`is_build_approved`) — the guest OS of the
//!        verified quote and the compose hash read from the CVM's boot event log, which must
//!        replay to the quote's RTMR3 (`replay_rtmr3`); an unreplayable log is "not approved".
//!
//! All outbound HTTP (Intel PCS via dcap-qvl's own client; NEAR RPC via our own) is bounded by
//! timeouts so a hung upstream cannot pile up background tasks. The endpoints contacted are fixed
//! constants (Intel PCS URL, fastnear RPC) and contract IDs derived only from role+network — never
//! request-derived, so there is no SSRF surface (../SECURITY.md req 2).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use attestation_shared::{CvmAttestation, EventLogEntry, Measurements, NodeReport, Role};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// dstack embeds the TDX quote in the RA-TLS leaf cert under this private-enterprise OID.
const QUOTE_EXT_OID: &str = "1.3.6.1.4.1.62397.1.8";
/// Intel TDX v4 quote header magic (version=4 LE, attestation_key_type=2 LE). We scan for this to
/// slice past the dstack framing prefix without relying on its exact length.
const TDX_QUOTE_MAGIC: [u8; 4] = [0x04, 0x00, 0x02, 0x00];
/// A real TDX v4 quote is several KiB; anything tiny means extraction grabbed garbage.
const MIN_QUOTE_LEN: usize = 1000;
/// Intel PCS — the upstream DCAP collateral source (queried directly, no Phala in the data path).
/// Fixed constant, not request-derived. dcap-qvl detects this base URL and uses Intel's `/sgx` and
/// `/tdx` certification v4 endpoints for the PCK CRL / TCB / QE-identity collateral.
const PCCS_URL: &str = dcap_qvl::collateral::INTEL_PCS_URL;
/// Bound every NEAR RPC call. dcap-qvl's PCCS client has its own (180s) internal timeout we accept.
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// fastnear RPC endpoints (never near.org). Picked by the CVM's network; not request-derived.
fn rpc_url(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("https://rpc.mainnet.fastnear.com"),
        "testnet" => Some("https://rpc.testnet.fastnear.com"),
        _ => None,
    }
}

/// The NEAR top-level account suffix for a network: **mainnet accounts end in `.near`**, testnet in
/// `.testnet`. So `worker.outlayer` on mainnet is `worker.outlayer.near`, NOT `worker.outlayer.mainnet`.
fn near_tla(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("near"),
        "testnet" => Some("testnet"),
        _ => None,
    }
}

/// The on-chain contract that holds the approved-measurements list for a (role, network) pair.
/// `Worker` → the register-contract; `Keystore` → the keystore DAO. Kms/Gateway/Unknown, a
/// net-agnostic CVM, or an unknown network have no applicable contract (returns `None` → on-chain
/// check skipped).
fn approval_contract(role: Role, network: &str) -> Option<String> {
    let tla = near_tla(network)?;
    match role {
        Role::Worker => Some(format!("worker.outlayer.{tla}")),
        Role::Keystore => Some(format!("dao.outlayer.{tla}")),
        Role::Kms | Role::Gateway | Role::Unknown => None,
    }
}

/// The fields decoded directly from the dcap-qvl-verified TDX quote, plus the raw quote hex.
///
/// All hex strings are lowercase (Intel-style); only `fmspc` is uppercase to match Intel's PCS
/// FMSPC convention (e.g. `B0C06F000000`). This is the data Phala's explorer shows under "TDX
/// Hardware Attestation" — the cryptographically-verified register values, not the report's
/// self-asserted ones. Every field is public, non-secret attestation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedReport {
    /// MRTD (`mr_td`) — virtual firmware measurement.
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    /// 64-byte REPORTDATA (binds the RA-TLS pubkey).
    pub report_data: String,
    /// MRSEAM — the Intel TDX module measurement.
    pub mr_seam: String,
    /// MRSIGNERSEAM — the TDX module signer.
    pub mr_signer_seam: String,
    /// TEE_TCB_SVN (16 bytes).
    pub tee_tcb_svn: String,
    /// TD_ATTRIBUTES (8 bytes) — TD debug/sec flags.
    pub td_attributes: String,
    /// XFAM (8 bytes) — extended features mask.
    pub xfam: String,
    /// PCK FMSPC (6 bytes, uppercase hex like `B0C06F000000`), or `None` if it could not be
    /// extracted from the quote's PCK cert chain (fail-soft — never blocks the verdict).
    pub fmspc: Option<String>,
    /// The entire raw Intel quote, lowercase hex — for independent re-verification (proof.t16z.com).
    pub quote_hex: String,
}

/// One CVM's verification outcome. Serialized into the stored report and served read-only at
/// `/api/attestation`, so every field here is public, non-secret attestation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvmVerdict {
    /// The vmm uuid this verdict is for (matches `CvmAttestation.vm_id`).
    pub vm_id: String,
    /// Did the full DCAP verification (quote signature + cert chain + TCB) pass? Fail-closed: any
    /// error along the way leaves this `false`.
    pub sig_valid: bool,
    /// Intel TCB status string from the verified report (`"UpToDate"`, `"OutOfDate"`, …). Only
    /// `"UpToDate"` is fully good; `None` if verification did not get far enough to produce one.
    pub tcb_status: Option<String>,
    /// Intel advisory IDs (INTEL-SA-…) attached to the matched TCB level, if any.
    pub advisory_ids: Vec<String>,
    /// PCK FMSPC (uppercase hex), extracted from the quote's PCK cert chain. `None` if it could
    /// not be extracted (fail-soft). Mirrors `decoded.fmspc` — kept at this level for the page's
    /// verdict row and backwards compatibility with the existing `/api/attestation` shape.
    pub fmspc: Option<String>,
    /// The fields decoded from the verified quote (registers, report_data, fmspc, raw quote hex).
    /// `None` until verification produces a TD report (not-yet-verified, extraction failure, or a
    /// non-TDX report) — the page degrades to the report's claimed measurements in that case.
    pub decoded: Option<DecodedReport>,
    /// Do the measurements parsed FROM the verified quote match the `measurements` the report
    /// claimed? `None` if we couldn't compare (no quote parsed, or report carried no measurements).
    pub quote_measurements_match: Option<bool>,
    /// Are these measurements on the on-chain approved list? `None` when the check is not applicable
    /// (kms/gateway/unknown role or no network) OR could not be performed (RPC error → see `error`).
    pub on_chain_approved: Option<bool>,
    /// Which contract was queried for `on_chain_approved` (for transparency on the page).
    pub on_chain_contract: Option<String>,
    /// First failure encountered, if any. Public-safe: dcap-qvl / parse / RPC error text only — no
    /// secrets or internal topology.
    pub error: Option<String>,
    /// Unix seconds when this verdict was produced.
    pub verified_at: u64,
}

impl CvmVerdict {
    /// A fresh, all-negative verdict for `vm_id`. Everything starts fail-closed; the pipeline only
    /// flips fields to positive on explicit success.
    fn new(vm_id: String) -> Self {
        CvmVerdict {
            vm_id,
            sig_valid: false,
            tcb_status: None,
            advisory_ids: Vec::new(),
            fmspc: None,
            decoded: None,
            quote_measurements_match: None,
            on_chain_approved: None,
            on_chain_contract: None,
            error: None,
            verified_at: now_secs(),
        }
    }
}

/// Extract the raw Intel TDX quote bytes from the RA-TLS leaf certificate.
///
/// `app_cert_pem` is a 3-cert PEM chain (leaf `CN=demo-cert`, then dstack App CA, then KMS CA).
/// The quote lives in the LEAF cert's X.509 extension `QUOTE_EXT_OID`. x509-parser's
/// `parse_x509_pem` decodes only the first PEM block (the leaf), and `X509Extension.value` gives the
/// extnValue content. Inside that there's a 4-byte dstack framing prefix; rather than trust its
/// length we scan for the TDX quote header magic and slice from there to the end.
pub fn extract_quote_from_app_cert(pem: &str) -> Result<Vec<u8>> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("PEM parse: {e}"))?;
    let cert = pem.parse_x509().context("parse leaf X.509 certificate")?;

    let ext = cert
        .iter_extensions()
        .find(|e| e.oid.to_id_string() == QUOTE_EXT_OID)
        .ok_or_else(|| anyhow!("quote extension {QUOTE_EXT_OID} not found in leaf cert"))?;

    // The extnValue content may itself be a DER OCTET STRING wrapping the dstack blob. Scanning for
    // the quote magic sidesteps any framing/length assumptions, so we search the raw value bytes
    // directly — the magic only appears at the start of the actual Intel quote.
    let blob = ext.value;
    let pos = blob
        .windows(TDX_QUOTE_MAGIC.len())
        .position(|w| w == TDX_QUOTE_MAGIC)
        .ok_or_else(|| anyhow!("TDX quote magic not found in cert extension"))?;
    let quote = &blob[pos..];

    if quote.len() < MIN_QUOTE_LEN {
        return Err(anyhow!(
            "extracted quote too short ({} bytes); extraction likely failed",
            quote.len()
        ));
    }
    Ok(quote.to_vec())
}

/// Verify a single CVM. Never panics; every failure path records `error` and leaves the relevant
/// positive fields unset (fail closed).
pub async fn verify_cvm(cvm: &CvmAttestation) -> CvmVerdict {
    let mut v = CvmVerdict::new(cvm.vm_id.clone());

    // 1. Need the RA-TLS cert to get a quote at all.
    let Some(pem) = cvm.app_cert_pem.as_deref() else {
        v.error = Some("no app_cert_pem in report (guest-agent unreachable?)".to_string());
        return v;
    };

    // 2. Extract the raw quote from the leaf cert.
    let quote = match extract_quote_from_app_cert(pem) {
        Ok(q) => q,
        Err(e) => {
            v.error = Some(format!("quote extraction failed: {e:#}"));
            return v;
        }
    };

    // 3. Fetch DCAP collateral directly from Intel PCS (network; dcap-qvl's own timed client) and
    //    verify. `with_default_http` builds an internal reqwest client; we accept its default timeout.
    let collateral = match dcap_qvl::collateral::CollateralClient::with_default_http(PCCS_URL) {
        Ok(client) => match client.fetch(&quote).await {
            Ok(c) => c,
            Err(e) => {
                v.error = Some(format!("Intel PCS collateral fetch failed: {e:#}"));
                return v;
            }
        },
        Err(e) => {
            v.error = Some(format!("Intel PCS client build failed: {e:#}"));
            return v;
        }
    };

    // dcap-qvl `verify()` is sync + CPU-bound; keep it off the async path is unnecessary here since
    // the whole verify runs in a spawned background task already (see main.rs). `verify()` returns
    // Err for a Revoked TCB (and any signature/chain failure) — we treat that as a hard fail.
    let verified = match dcap_qvl::verify::verify(&quote, &collateral, now_secs()) {
        Ok(r) => r,
        Err(e) => {
            v.error = Some(format!("quote verification failed: {e:#}"));
            return v;
        }
    };

    // Signature + cert chain + TCB chain all checked out (TCB not Revoked).
    v.sig_valid = true;
    v.tcb_status = Some(verified.status.clone());
    v.advisory_ids = verified.advisory_ids.clone();

    // Decode the register/report fields straight from the verified quote and extract the FMSPC from
    // the embedded PCK cert chain. Both are best-effort presentation data: a failure here MUST NOT
    // flip the verdict (the signature/TCB/measurement checks above are what decide trust). So the
    // whole thing is fail-soft — `decoded`/`fmspc` simply stay `None` on any decode error.
    let fmspc = extract_fmspc(&quote);
    v.fmspc = fmspc.clone();
    v.decoded = decode_report(&verified, &quote, fmspc);

    // 4. Bind the verified quote to the measurements the report claimed. If they don't match, the
    //    rendered measurements are NOT the ones that were cryptographically verified — a red flag.
    if let Some(claimed) = cvm.measurements.as_ref() {
        match quote_measurements(&verified) {
            Some(from_quote) => {
                v.quote_measurements_match = Some(measurements_eq(&from_quote, claimed));
            }
            None => {
                // Verified but not a TD report (e.g. plain SGX) — can't compare TDX RTMRs.
                v.quote_measurements_match = Some(false);
                v.error
                    .get_or_insert_with(|| "verified quote is not a TDX TD10/TD15 report".to_string());
            }
        }
    }

    // 5. On-chain cross-check (worker/keystore on their network only).
    let network = cvm.network.as_deref();
    if let Some(net) = network {
        if let (Role::Keystore, Some(contract)) = (cvm.role, approval_contract(cvm.role, net)) {
            v.on_chain_contract = Some(contract.clone());
            // The build is read from the verified quote and the log that replays to it — never
            // from the report's claimed measurements or compose hash.
            let build = quote_measurements(&verified)
                .ok_or_else(|| anyhow!("verified quote is not a TDX report"))
                .and_then(|q| {
                    let (rtmr3, compose_hash) = replay_rtmr3(&cvm.event_log)?;
                    if !hex_eq(&rtmr3, &q.rtmr3) {
                        return Err(anyhow!("the boot event log does not replay to the quote's RTMR3"));
                    }
                    Ok((q, compose_hash))
                });
            match build {
                Ok((q, compose_hash)) => match check_build_on_chain(&contract, net, &q, &compose_hash).await {
                    Ok(approved) => v.on_chain_approved = Some(approved),
                    Err(e) => {
                        v.error
                            .get_or_insert_with(|| format!("on-chain check failed: {e:#}"));
                    }
                },
                Err(e) => {
                    // No build can be read from this CVM: not approved, and the reason shown.
                    v.on_chain_approved = Some(false);
                    v.error.get_or_insert_with(|| format!("keystore build: {e:#}"));
                }
            }
        } else if let Some(contract) = approval_contract(cvm.role, net) {
            v.on_chain_contract = Some(contract.clone());
            match cvm.measurements.as_ref() {
                Some(m) => match check_on_chain(&contract, net, m).await {
                    Ok(approved) => v.on_chain_approved = Some(approved),
                    Err(e) => {
                        // RPC failure: leave `on_chain_approved = None` (unknown, not "approved").
                        v.error
                            .get_or_insert_with(|| format!("on-chain check failed: {e:#}"));
                    }
                },
                None => {
                    v.error.get_or_insert_with(|| {
                        "no measurements in report; cannot run on-chain check".to_string()
                    });
                }
            }
        }
    }

    v
}

/// Verify every CVM in a node report, in order. Sequential is fine: a node carries a handful of
/// CVMs and each verify is dominated by its own network round-trips, which are individually bounded.
pub async fn verify_report(report: &NodeReport) -> Vec<CvmVerdict> {
    let mut out = Vec::with_capacity(report.cvms.len());
    for cvm in &report.cvms {
        out.push(verify_cvm(cvm).await);
    }
    out
}

/// Extract the FMSPC (6 bytes) from the quote's embedded PCK cert chain, as uppercase hex
/// (`B0C06F000000`, matching Intel's PCS convention). Fail-soft: any parse error → `None`, never a
/// panic. dcap-qvl already parses the PCK SGX extension (OID 1.2.840.113741.1.13.1.4) internally,
/// so we reuse its `intel::quote_fmspc` rather than re-implementing x509/DER walking.
fn extract_fmspc(raw_quote: &[u8]) -> Option<String> {
    let quote = dcap_qvl::quote::Quote::parse(raw_quote).ok()?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&quote).ok()?;
    Some(hex_upper(&fmspc))
}

/// Decode the per-register/report fields from the verified quote into a `DecodedReport`. Returns
/// `None` for a non-TDX (SGX) report — there are no TDX registers to show. Fail-soft by
/// construction (only field copies + hex encoding; no fallible external calls).
fn decode_report(
    verified: &dcap_qvl::verify::VerifiedReport,
    raw_quote: &[u8],
    fmspc: Option<String>,
) -> Option<DecodedReport> {
    let td = verified.report.as_td10()?;
    Some(DecodedReport {
        mrtd: hex_lower(&td.mr_td),
        rtmr0: hex_lower(&td.rt_mr0),
        rtmr1: hex_lower(&td.rt_mr1),
        rtmr2: hex_lower(&td.rt_mr2),
        rtmr3: hex_lower(&td.rt_mr3),
        report_data: hex_lower(&td.report_data),
        mr_seam: hex_lower(&td.mr_seam),
        mr_signer_seam: hex_lower(&td.mr_signer_seam),
        tee_tcb_svn: hex_lower(&td.tee_tcb_svn),
        td_attributes: hex_lower(&td.td_attributes),
        xfam: hex_lower(&td.xfam),
        fmspc,
        quote_hex: hex_lower(raw_quote),
    })
}

/// Pull the 5 TDX registers out of a verified report as `Measurements` (hex strings), or `None` if
/// the report is not a TD10/TD15 (e.g. an SGX enclave report).
fn quote_measurements(verified: &dcap_qvl::verify::VerifiedReport) -> Option<Measurements> {
    let td = verified.report.as_td10()?;
    Some(Measurements {
        mrtd: hex_lower(&td.mr_td),
        rtmr0: hex_lower(&td.rt_mr0),
        rtmr1: hex_lower(&td.rt_mr1),
        rtmr2: hex_lower(&td.rt_mr2),
        rtmr3: hex_lower(&td.rt_mr3),
    })
}

/// Compare two measurement sets, case-insensitively on the hex (the report may use either case).
fn measurements_eq(a: &Measurements, b: &Measurements) -> bool {
    hex_eq(&a.mrtd, &b.mrtd)
        && hex_eq(&a.rtmr0, &b.rtmr0)
        && hex_eq(&a.rtmr1, &b.rtmr1)
        && hex_eq(&a.rtmr2, &b.rtmr2)
        && hex_eq(&a.rtmr3, &b.rtmr3)
}

fn hex_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The five registers as the contracts' `measurements` argument.
fn measurements_json(m: &Measurements) -> serde_json::Value {
    serde_json::json!({
        "mrtd": m.mrtd,
        "rtmr0": m.rtmr0,
        "rtmr1": m.rtmr1,
        "rtmr2": m.rtmr2,
        "rtmr3": m.rtmr3,
    })
}

/// A worker: `is_measurements_approved(measurements)` on the register contract.
async fn check_on_chain(contract: &str, network: &str, m: &Measurements) -> Result<bool> {
    let args = serde_json::json!({ "measurements": measurements_json(m) });
    view_bool(contract, network, "is_measurements_approved", &args).await
}

/// A keystore: `is_build_approved(measurements, compose_hash)` on the keystore DAO — its guest OS
/// (MRTD, RTMR0-2) and its compose on the lists approved by vote.
async fn check_build_on_chain(
    contract: &str,
    network: &str,
    m: &Measurements,
    compose_hash: &str,
) -> Result<bool> {
    let args = serde_json::json!({ "measurements": measurements_json(m), "compose_hash": compose_hash });
    view_bool(contract, network, "is_build_approved", &args).await
}

/// The register a dstack guest extends with its boot events.
const APP_IMR: u32 = 3;
/// The guest OS's last boot event: facts are read only before it.
const BOOT_END: &str = "system-ready";
/// Bounds of a log, as the keystore DAO sets them.
const MAX_EVENTS: usize = 64;
const MAX_PAYLOAD_HEX: usize = 1024;

/// RTMR3 replayed from a dstack boot event log, and the compose hash the guest OS recorded before
/// `system-ready`. The rules are the keystore DAO's (keystore-dao-contract/src/event_log.rs): each
/// digest is sha384(event_type as u32 LE ‖ ":" ‖ event ‖ ":" ‖ payload) computed from the fields —
/// a digest in the log is not read — and RTMR3 = fold sha384(mr ‖ digest) from 48 zero bytes over
/// the IMR-3 events in order. At most 64 events, payloads at most 1024 hex, an event name without
/// ':' and at most 64 bytes, exactly one 64-hex `compose-hash` before `system-ready`.
fn replay_rtmr3(log: &[EventLogEntry]) -> Result<(String, String)> {
    use sha2::{Digest, Sha384};
    if log.len() > MAX_EVENTS {
        return Err(anyhow!("event log has {} entries, at most {MAX_EVENTS}", log.len()));
    }
    let mut mr = [0u8; 48];
    let mut booted = false;
    let mut compose_hash: Option<String> = None;
    for e in log.iter().filter(|e| e.imr == APP_IMR) {
        let name = e.event.as_deref().unwrap_or("");
        let payload_hex = e.event_payload.as_deref().unwrap_or("");
        if payload_hex.len() > MAX_PAYLOAD_HEX {
            return Err(anyhow!("event '{name}': payload too long"));
        }
        // The digest is over `type:name:payload`: a name with a colon could be read as two events.
        if name.is_empty() || name.contains(':') || name.len() > 64 {
            return Err(anyhow!("event name '{name}' is not one dstack writes"));
        }
        let event_type = u32::try_from(e.event_type)
            .map_err(|_| anyhow!("event '{name}': event_type {} is not 32-bit", e.event_type))?;
        let payload = hex_decode(payload_hex)
            .ok_or_else(|| anyhow!("event '{name}': payload is not hex"))?;
        let mut h = Sha384::new();
        h.update(event_type.to_le_bytes());
        h.update(b":");
        h.update(name.as_bytes());
        h.update(b":");
        h.update(&payload);
        let digest = h.finalize();
        let mut ext = Sha384::new();
        ext.update(mr);
        ext.update(digest);
        mr.copy_from_slice(&ext.finalize());
        if booted {
            continue;
        }
        match name {
            BOOT_END => booted = true,
            "compose-hash" => {
                if compose_hash.is_some() {
                    return Err(anyhow!("event 'compose-hash' appears twice before {BOOT_END}"));
                }
                compose_hash = Some(payload_hex.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    if !booted {
        return Err(anyhow!("event log has no {BOOT_END} event"));
    }
    let compose_hash =
        compose_hash.ok_or_else(|| anyhow!("event log has no compose-hash before {BOOT_END}"))?;
    if compose_hash.len() != 64 {
        return Err(anyhow!("compose-hash is {} hex characters, not 64", compose_hash.len()));
    }
    Ok((hex_lower(&mr), compose_hash))
}

/// Decode hex (either case); `None` on an odd length or a non-hex character.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
}

/// A NEAR JSON-RPC view call of `method` on `contract` that returns a bool. Any transport /
/// decode error is an `Err` (→ the verdict's `on_chain_approved` stays `None`, i.e. unknown —
/// never silently "approved").
async fn view_bool(contract: &str, network: &str, method: &str, args: &serde_json::Value) -> Result<bool> {
    let url = rpc_url(network).ok_or_else(|| anyhow!("no RPC URL for network {network}"))?;
    let args_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(args).context("serialize view args")?);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "query",
        "params": {
            "request_type": "call_function",
            "finality": "final",
            "account_id": contract,
            "method_name": method,
            "args_base64": args_b64,
        }
    });

    let client = reqwest::Client::builder()
        .connect_timeout(RPC_TIMEOUT)
        .timeout(RPC_TIMEOUT)
        .build()
        .context("build RPC client")?;

    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .context("RPC request")?;
    if !resp.status().is_success() {
        return Err(anyhow!("RPC HTTP {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await.context("decode RPC JSON")?;

    // Surface a contract/RPC-level error rather than misreading it as a false negative.
    if let Some(err) = json.get("error") {
        return Err(anyhow!("RPC error: {err}"));
    }

    // A failed view (no such method, a panic) answers `.result.error`, a string, instead.
    if let Some(err) = json.get("result").and_then(|r| r.get("error")).and_then(|e| e.as_str()) {
        return Err(anyhow!("{method} on {contract}: {err}"));
    }

    // The view result is at `.result.result`: a byte array that decodes to the JSON return value.
    let bytes_val = json
        .get("result")
        .and_then(|r| r.get("result"))
        .ok_or_else(|| anyhow!("RPC response missing result.result"))?;
    let bytes: Vec<u8> = serde_json::from_value(bytes_val.clone())
        .context("result.result is not a byte array")?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).context("view return value is not JSON")?;
    parsed
        .as_bool()
        .ok_or_else(|| anyhow!("{method} did not return a bool"))
}

/// Lowercase-hex a byte slice without pulling in the `hex` crate (deps stay minimal — SECURITY.md).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Uppercase-hex a byte slice (Intel FMSPC convention, e.g. `B0C06F000000`).
fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
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

    #[test]
    fn hex_lower_roundtrip() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff, 0xab]), "000fffab");
        assert_eq!(hex_lower(&[0u8; 48]).len(), 96);
    }

    #[test]
    fn hex_eq_is_case_insensitive() {
        assert!(hex_eq("ABCDEF", "abcdef"));
        assert!(!hex_eq("abcd", "abce"));
    }

    #[test]
    fn approval_contract_by_role() {
        assert_eq!(
            approval_contract(Role::Worker, "mainnet").as_deref(),
            Some("worker.outlayer.near")
        );
        assert_eq!(
            approval_contract(Role::Worker, "testnet").as_deref(),
            Some("worker.outlayer.testnet")
        );
        assert_eq!(
            approval_contract(Role::Keystore, "mainnet").as_deref(),
            Some("dao.outlayer.near")
        );
        assert_eq!(
            approval_contract(Role::Keystore, "testnet").as_deref(),
            Some("dao.outlayer.testnet")
        );
        assert_eq!(approval_contract(Role::Kms, "mainnet"), None);
        assert_eq!(approval_contract(Role::Gateway, "mainnet"), None);
        assert_eq!(approval_contract(Role::Unknown, "testnet"), None);
    }

    /// The real v0.2.5 keystore registration: its boot events as the keystore sent them (digests
    /// empty) and the RTMR3 of its TDX quote.
    fn v025() -> (Vec<EventLogEntry>, String, String) {
        let d: serde_json::Value =
            serde_json::from_str(include_str!("testdata/keystore_v025_log.json")).unwrap();
        let events: Vec<EventLogEntry> = serde_json::from_value(d["events"].clone()).unwrap();
        (events, d["quote_rtmr3"].as_str().unwrap().to_string(), d["compose_hash"].as_str().unwrap().to_string())
    }

    fn set_payload(log: &mut [EventLogEntry], event: &str, payload: &str) {
        let e = log.iter_mut().find(|e| e.event.as_deref() == Some(event)).unwrap();
        e.event_payload = Some(payload.to_string());
    }

    #[test]
    fn a_real_keystore_log_replays_to_its_quote_and_names_its_compose() {
        let (log, rtmr3, compose) = v025();
        let (got, got_compose) = replay_rtmr3(&log).unwrap();
        assert_eq!(got, rtmr3);
        assert_eq!(got_compose, compose);
    }

    #[test]
    fn a_digest_in_the_log_is_not_read() {
        let (mut log, rtmr3, _) = v025();
        for e in log.iter_mut() {
            e.digest = "ff".repeat(48);
        }
        assert_eq!(replay_rtmr3(&log).unwrap().0, rtmr3);
    }

    #[test]
    fn a_changed_fact_no_longer_replays_to_the_quote() {
        let (mut log, rtmr3, _) = v025();
        set_payload(&mut log, "compose-hash", &"ab".repeat(32));
        let (got, compose) = replay_rtmr3(&log).unwrap();
        assert_ne!(got, rtmr3, "another compose must give another RTMR3");
        assert_eq!(compose, "ab".repeat(32));
        let (mut log, rtmr3, _) = v025();
        set_payload(&mut log, "instance-id", &"00".repeat(20));
        assert_ne!(replay_rtmr3(&log).unwrap().0, rtmr3);
    }

    #[test]
    fn events_of_other_registers_do_not_count() {
        let (mut log, rtmr3, _) = v025();
        let mut other = log[0].clone();
        other.imr = 1;
        other.event = Some("compose-hash".into());
        other.event_payload = Some("cd".repeat(32));
        log.insert(0, other);
        let (got, compose) = replay_rtmr3(&log).unwrap();
        assert_eq!(got, rtmr3);
        assert_ne!(compose, "cd".repeat(32));
    }

    #[test]
    fn a_compose_hash_after_system_ready_is_not_the_build() {
        let (mut log, _, compose) = v025();
        let mut late = log.iter().find(|e| e.event.as_deref() == Some("compose-hash")).unwrap().clone();
        late.event_payload = Some("cd".repeat(32));
        log.push(late);
        assert_eq!(replay_rtmr3(&log).unwrap().1, compose);
    }

    #[test]
    fn a_log_the_dao_would_refuse_is_refused() {
        let refused = |f: &dyn Fn(&mut Vec<EventLogEntry>), why: &str| {
            let (mut log, _, _) = v025();
            f(&mut log);
            let e = replay_rtmr3(&log).expect_err(why).to_string();
            assert!(e.contains(why), "{why}: got '{e}'");
        };
        refused(&|l| { let c = l.iter().find(|e| e.event.as_deref() == Some("compose-hash")).unwrap().clone(); l.insert(3, c); }, "appears twice");
        refused(&|l| l.retain(|e| e.event.as_deref() != Some("system-ready")), "no system-ready");
        refused(&|l| l.retain(|e| e.event.as_deref() != Some("compose-hash")), "no compose-hash");
        refused(&|l| set_payload(l, "compose-hash", "abcd"), "not 64");
        refused(&|l| set_payload(l, "app-id", "zz"), "not hex");
        refused(&|l| set_payload(l, "app-id", &"a".repeat(1026)), "too long");
        refused(&|l| l[0].event = Some("app-id:x".into()), "not one dstack writes");
        refused(&|l| l[0].event = None, "not one dstack writes");
        refused(&|l| l[0].event_type = 1 << 32, "not 32-bit");
        refused(&|l| { let e = l[0].clone(); l.extend(std::iter::repeat(e).take(MAX_EVENTS)); }, "at most 64");
    }

    #[test]
    fn hex_decode_either_case_and_nothing_else() {
        assert_eq!(hex_decode("00fFa1"), Some(vec![0x00, 0xff, 0xa1]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn rpc_url_known_networks_only() {
        assert!(rpc_url("mainnet").is_some());
        assert!(rpc_url("testnet").is_some());
        assert!(rpc_url("devnet").is_none());
    }

    #[test]
    fn extract_quote_rejects_non_pem() {
        assert!(extract_quote_from_app_cert("not a pem").is_err());
    }

    #[test]
    fn measurements_eq_compares_all_registers() {
        let base = Measurements {
            mrtd: "AA".into(),
            rtmr0: "bb".into(),
            rtmr1: "cc".into(),
            rtmr2: "dd".into(),
            rtmr3: "ee".into(),
        };
        let same = Measurements {
            mrtd: "aa".into(),
            rtmr0: "BB".into(),
            rtmr1: "cc".into(),
            rtmr2: "dd".into(),
            rtmr3: "ee".into(),
        };
        assert!(measurements_eq(&base, &same));
        let diff = Measurements {
            rtmr3: "ef".into(),
            ..same.clone()
        };
        assert!(!measurements_eq(&base, &diff));
    }
}
