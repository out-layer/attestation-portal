//! Phase 3 — the public, server-side HTML attestation page for `workers.outlayer.ai`.
//!
//! This renders the attestation data the server already holds (the latest `NodeReport` per node)
//! joined with the Phase 2 per-CVM `CvmVerdict`s. It is the human-facing counterpart to
//! `/api/attestation`: same data, presented so a visitor can SEE that each CVM is a genuine Intel
//! TDX TEE running the on-chain-approved code.
//!
//! Two-level UX (modeled on Phala's explorer):
//!   * `render_index` — the LIST: one compact row per APP (grouped by `app_id`), not per running
//!     instance — multiple instances (e.g. two worker instances) share one `app_id` and collapse to
//!     a single row showing a display name, role/network badges, an instance count ("N instances"
//!     when N>1), an aggregate status, and an AGGREGATE verdict chip (failing if ANY instance fails;
//!     pending if ANY is pending; Verified only if ALL pass), grouped under their node_id header.
//!     Each row links to `/app/<app_id>` (the detail page renders every instance).
//!   * `render_app` — the DETAIL: the full per-CVM stack of "verified aspect" sections (App header,
//!     TDX Hardware Attestation, Source Code/compose, Zero Trust Gateway, App OS, KMS/Root-of-Trust)
//!     for every CVM whose `app_id` matches — multiple running instances can share one app_id, so all
//!     matching instances render (each its own card). An unknown app_id yields `None` so the handler
//!     can serve a friendly 404 instead of panicking.
//!
//! Honesty constraint (../SECURITY.md, MEMORY): we verify the quote's Intel DCAP signature + TCB
//! chain against Intel's PCS collateral directly (implementation: dcap-qvl), NOT Intel Trust
//! Authority — the page never claims "ITA Certified" and keeps the honest "not Intel Trust Authority"
//! disclaimer (on the detail page).
//!
//! Design notes / security (../SECURITY.md):
//!   * The templates (`templates/*.html`) are compiled by askama and **auto-escape every `{{ }}`
//!     expression**. Names / ids / hashes / the app-compose all ultimately arrive over the wire (a
//!     pushed report), so auto-escaping is our XSS defense — NO field is ever marked `|safe`. A
//!     `<script>` in a CVM name or in app_compose comes out as `&lt;script&gt;`.
//!   * We render to a `String` and let the caller wrap it in `axum::response::Html` — no
//!     `askama_axum` dependency (minimal attack surface).
//!   * All the joining (verdict ↔ cvm) and the freshness math happen HERE, in Rust, so the template
//!     stays a dumb, side-effect-free formatter. No panics: the page is built from already-stored,
//!     public data and never `.unwrap()`s a wire value.

use askama::Template;
use attestation_shared::{CvmAttestation, Measurements, NodeReport, Role};

use crate::verify::{CvmVerdict, DecodedReport};

// ---------------------------------------------------------------------------------------------
// View model — what the template actually renders. Built in Rust from (report, received_at,
// verdicts) so the template does zero logic. Everything is owned `String`s / simple enums.
// ---------------------------------------------------------------------------------------------

/// Freshness of a node's last push, bucketed for coloring the "last seen live" pill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Pushed < 10 min ago — the agent is alive.
    Live,
    /// 10 min – 1 h — late, but not yet presumed dead.
    Stale,
    /// > 1 h — the agent has stopped reporting.
    Dead,
}

impl Freshness {
    /// CSS class suffix used by the template (`pill-live` / `pill-stale` / `pill-dead`).
    fn class(self) -> &'static str {
        match self {
            Freshness::Live => "live",
            Freshness::Stale => "stale",
            Freshness::Dead => "dead",
        }
    }
}

/// On-chain approval as a renderable tri-state. `Some(true)` = approved (green), `Some(false)` =
/// NOT approved (loud red), `None` = not applicable / unknown (grey).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnChain {
    Approved,
    NotApproved,
    /// kms/gateway/unknown role, or the check couldn't run (RPC error) — neither a pass nor a fail.
    NotApplicable,
}

/// The compact, one-glance verdict shown on each index row. Collapses the full per-facet verdict into
/// a single tri-state: GREEN when every concrete check passes, RED when any fails, GREY while the
/// background verification is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Summary {
    /// sig_valid && tcb UpToDate && (on_chain approved || n/a) && measurements match.
    Verified,
    /// Any concrete facet failed (bad signature, NOT-approved on-chain, mismatch, or verify error).
    Failed,
    /// No verdict yet — verification still in flight.
    Pending,
}

impl Summary {
    /// CSS class suffix used by the template (`sum-verified` / `sum-failed` / `sum-pending`).
    fn class(self) -> &'static str {
        match self {
            Summary::Verified => "verified",
            Summary::Failed => "failed",
            Summary::Pending => "pending",
        }
    }
    /// The short label rendered in the row chip.
    fn label(self) -> &'static str {
        match self {
            Summary::Verified => "✓ Verified",
            Summary::Failed => "✗ Check failed",
            Summary::Pending => "verifying…",
        }
    }

    /// Fold a group of per-instance summaries into the app's AGGREGATE summary, with `Failed`
    /// dominating: an app row is `Failed` if ANY instance failed, else `Pending` if ANY instance is
    /// still verifying, else `Verified` only when EVERY instance passed. An empty group (never
    /// happens for a real app row — a group exists because it has ≥1 instance) reads as `Pending`.
    fn aggregate(summaries: impl IntoIterator<Item = Summary>) -> Summary {
        let mut any_failed = false;
        let mut any_pending = false;
        let mut any = false;
        for s in summaries {
            any = true;
            match s {
                Summary::Failed => any_failed = true,
                Summary::Pending => any_pending = true,
                Summary::Verified => {}
            }
        }
        if any_failed {
            Summary::Failed
        } else if any_pending || !any {
            Summary::Pending
        } else {
            Summary::Verified
        }
    }
}

/// One node (one TDX host) as the INDEX list sees it: its header (id + freshness pill) plus the
/// compact rows for its APPS. Each row is a thin `AppRowView` (no decoded quote / sections) so the
/// list stays light; the full per-CVM view (`CvmView`) is built only on the detail page.
pub struct NodeListView {
    pub node_id: String,
    pub last_seen_human: String,
    pub last_seen_class: &'static str,
    pub rows: Vec<AppRowView>,
}

/// One compact index row for an APP (a distinct `app_id` within a node), collapsing every running
/// instance that shares that `app_id` into a single line — the few fields a visitor scans before
/// clicking through. The row links to `/app/<app_id>` (the detail page renders every instance).
/// Every field is escaped-safe text/flag.
pub struct AppRowView {
    /// Display name for the app: the first instance's name with an obvious trailing instance-number
    /// suffix trimmed (e.g. `mainnet-worker-1` → `mainnet-worker`); the raw first name otherwise.
    pub name: String,
    pub role_label: &'static str,
    /// "mainnet" / "testnet" badge, or `None` for net-agnostic CVMs (kms, gateway). Taken from the
    /// group (instances of one app share role + network).
    pub network_label: Option<String>,
    /// Aggregate status: the shared status string when all instances agree, else a compact mixed
    /// indicator like "2 running / 3" (or just "mixed" when none are running).
    pub status: String,
    /// How many instances share this `app_id`. ≥ 1.
    pub instance_count: usize,
    /// `true` only when `instance_count > 1` — gates the "N instances" count chip in the template.
    pub multi_instance: bool,
    /// The app identity this row links to (`/app/<app_id>`). May be empty on a degraded report.
    pub app_id: String,
    /// "verified" | "failed" | "pending" — drives the summary-chip color (AGGREGATE over instances).
    pub summary_class: &'static str,
    /// "✓ Verified" | "✗ Check failed" | "verifying…" (AGGREGATE over instances).
    pub summary_label: &'static str,
}

/// One CVM, rendered as a vertical stack of "verified aspect" sections. Every field is already
/// escaped-safe text/flag; the template only formats it.
pub struct CvmView {
    // ---- App header section ----
    pub name: String,
    pub role_label: &'static str,
    /// "mainnet" / "testnet" badge, or `None` for net-agnostic CVMs (kms, gateway).
    pub network_label: Option<String>,
    pub status: String,
    pub uptime: Option<String>,
    pub app_id: String,
    /// The dstack vmm uuid of this instance — shown on the card so two instances that share an
    /// `app_id` (and may even share a name) are still distinguishable.
    pub vm_id: String,
    /// This card's position among the instances sharing the `app_id`: 1-based index and the total.
    /// Rendered as "instance N of M" only when M > 1 (a single instance shows no marker).
    pub instance_index: usize,
    pub instance_total: usize,
    /// True when the key provider is the dstack KMS (keys managed in-TEE), false for local-sgx.
    pub kms_in_tee: bool,
    /// The Zero-Trust-Gateway domain guarded for this CVM (`<app_id>-8081.dstack.outlayer.ai` for a
    /// keystore; role-appropriate), or `None` (n/a) for gateway/kms/unknown.
    pub gateway_domain: Option<String>,

    // ---- TDX Hardware Attestation section ----
    pub verdict: VerdictView,
    /// The fields decoded straight from the verified quote (registers, report_data, fmspc, raw quote
    /// hex). `None` until verification produced a TD report — the page then degrades to the report's
    /// claimed `measurements` rows below.
    pub decoded: Option<DecodedReportView>,
    /// The report's *claimed* TDX registers (the fallback when `decoded` is None). Pre-flattened to
    /// (label, hex) rows.
    pub measurements: Vec<MeasurementRow>,

    // ---- Source Code (compose) section ----
    /// The raw app-compose JSON, if the agent reported it (None on older agents → "not reported yet").
    pub app_compose: Option<String>,
    pub image_digests: Vec<String>,
    /// The per-image table (Container | Image | Digest | Verify), parsed from the measured compose.
    /// Empty if no `image: …@sha256:…` lines could be parsed (older report or unexpected format).
    pub images: Vec<ImageRow>,

    // ---- App OS section ----
    /// dstack guest OS image tag (e.g. `dstack-0.5.11`), parsed dynamically from the CVM's
    /// `vm_config.image`. `None` on older agents → the page shows only `os_image_hash`.
    pub os_version: Option<String>,
    pub os_image_hash: Option<String>,
    pub mr_aggregated: Option<String>,
    pub compose_hash: Option<String>,

    // ---- KMS / Root of Trust section ----
    pub key_provider: Option<String>,

    /// Per-CVM collection error from the agent (guest-agent unreachable, etc.), if any.
    pub collect_error: Option<String>,
}

/// The decoded-from-quote register/report block (TDX Hardware Attestation section). Pre-flattened
/// for the template; `fmspc` kept separate so it can be highlighted in the verdict row too.
pub struct DecodedReportView {
    pub rows: Vec<MeasurementRow>,
    pub fmspc: Option<String>,
    /// The full raw Intel quote as lowercase hex (goes in a selectable `<pre>`).
    pub quote_hex: String,
}

/// One labeled hex row (a measurement register or a decoded report field).
pub struct MeasurementRow {
    pub label: &'static str,
    pub value: String,
}

/// One row of the Source-Code image table: a container's measured image + its provenance links.
/// Built in Rust from the measured `docker_compose_file`; the template only formats these strings
/// (all auto-escaped — including the URLs, which are plain attributes, never `|safe`).
pub struct ImageRow {
    /// docker-compose service name (the key under `services:`), or `image` if it couldn't be paired.
    pub container: String,
    /// Image reference without the digest, e.g. `docker.io/outlayer/near-outlayer-keystore`.
    pub image: String,
    /// The measured `sha256:<hex>` digest (this is the value bound into RTMR3 via the compose hash).
    pub digest: String,
    /// `https://search.sigstore.dev/?hash=sha256:<digest>` — ties the digest to its build provenance.
    pub sigstore_url: String,
    /// For OutLayer-built images, the GitHub release tag URL (`…/releases/tag/v<version>`); `None`
    /// for non-OutLayer (dstack system) images, which carry only the digest + Sigstore link.
    pub release_url: Option<String>,
    /// Honest provenance origin label: `"OutLayer-built"` or `"dstack system image"`.
    pub origin: &'static str,
}

/// The verification verdict, flattened to render-ready flags + strings.
pub struct VerdictView {
    /// True while no verdict exists yet (verification still running) — show "verifying…".
    pub pending: bool,
    /// DCAP signature + cert chain + TCB verification passed.
    pub sig_valid: bool,
    /// Intel TCB status string, e.g. "UpToDate". `None` if verification didn't get that far.
    pub tcb_status: Option<String>,
    /// "good" (UpToDate) | "warn" (other) | "bad" (none) — colors the TCB badge.
    pub tcb_class: &'static str,
    /// Did measurements parsed from the verified quote match the report's claimed ones?
    pub measurements_match: Option<bool>,
    pub on_chain: OnChain,
    /// Which contract the on-chain check queried (shown for transparency).
    pub on_chain_contract: Option<String>,
    pub advisory_ids: Vec<String>,
    /// First failure text from the verify pipeline, if any (public-safe per verify.rs).
    pub verify_error: Option<String>,
    /// True if ANY verdict facet is failing — flips the whole card to the loud/red state.
    pub failing: bool,
}

impl OnChain {
    /// CSS class suffix (`oc-approved` / `oc-bad` / `oc-na`). `pub` so the template can call it.
    pub fn class(self) -> &'static str {
        match self {
            OnChain::Approved => "approved",
            OnChain::NotApproved => "bad",
            OnChain::NotApplicable => "na",
        }
    }
    pub fn approved(self) -> bool {
        matches!(self, OnChain::Approved)
    }
    pub fn not_approved(self) -> bool {
        matches!(self, OnChain::NotApproved)
    }
}

impl VerdictView {
    fn tcb_class_of(status: Option<&str>) -> &'static str {
        match status {
            Some("UpToDate") => "good",
            Some(_) => "warn",
            None => "bad",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Builders — the verdict↔cvm join + freshness math live here.
// ---------------------------------------------------------------------------------------------

/// Human-readable role label for a badge.
fn role_label(role: Role) -> &'static str {
    match role {
        Role::Kms => "KMS",
        Role::Gateway => "Gateway",
        Role::Keystore => "Keystore",
        Role::Worker => "Worker",
        Role::Unknown => "Unknown",
    }
}

/// The Zero-Trust-Gateway domain a CVM's traffic terminates at, computed from its `app_id`. dstack's
/// per-app gateway exposes a service as `<app_id>-<port>.dstack.outlayer.ai`. Keystore + worker
/// services front on `:8081`; gateway/kms/unknown have no app-fronted port (returns `None` → "n/a").
fn gateway_domain(role: Role, app_id: &str) -> Option<String> {
    if app_id.is_empty() {
        return None;
    }
    match role {
        Role::Keystore | Role::Worker => Some(format!("{app_id}-8081.dstack.outlayer.ai")),
        Role::Kms | Role::Gateway | Role::Unknown => None,
    }
}

/// Bucket `received_at` (unix secs) into a freshness class given `now`.
fn freshness(now: u64, received_at: u64) -> Freshness {
    let age = now.saturating_sub(received_at);
    if age < 600 {
        Freshness::Live
    } else if age < 3600 {
        Freshness::Stale
    } else {
        Freshness::Dead
    }
}

/// "12s ago" / "4m ago" / "2h ago" / "3d ago". Coarse on purpose — this is a liveness signal, not a
/// clock. Future timestamps (clock skew) read as "just now".
fn humanize_age(now: u64, received_at: u64) -> String {
    let age = now.saturating_sub(received_at);
    if age < 5 {
        "just now".to_string()
    } else if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86_400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86_400)
    }
}

/// Flatten the report's *claimed* 5 TDX registers into ordered rows. `None` (guest-agent
/// unreachable) → no rows.
fn measurement_rows(m: Option<&Measurements>) -> Vec<MeasurementRow> {
    let Some(m) = m else {
        return Vec::new();
    };
    vec![
        MeasurementRow { label: "mrtd", value: m.mrtd.clone() },
        MeasurementRow { label: "rtmr0", value: m.rtmr0.clone() },
        MeasurementRow { label: "rtmr1", value: m.rtmr1.clone() },
        MeasurementRow { label: "rtmr2", value: m.rtmr2.clone() },
        MeasurementRow { label: "rtmr3", value: m.rtmr3.clone() },
    ]
}

/// Parse the per-image table from the measured app-compose JSON.
///
/// `app_compose` is the raw `tcb_info.app_compose` JSON string: it carries `name` (e.g.
/// `outlayer-worker-testnet-0.1.35`) and `docker_compose_file` (the compose YAML text). We pull every
/// `image: <ref>@sha256:<digest>` line out of the compose, pairing each with the nearest preceding
/// `services:` child key as the container name. For OutLayer images (`*/outlayer/*` on docker.io)
/// we also surface a GitHub release link derived from the trailing version in `name`; non-OutLayer
/// images (dstack system images like `dstacktee/dstack-kms`) get only the digest + Sigstore link and
/// an honest "dstack system image" origin label.
///
/// Pure string work, no fallible external calls; an unparseable compose simply yields `vec![]`
/// (the template then falls back to the raw compose block alone).
fn image_rows(app_compose: Option<&str>) -> Vec<ImageRow> {
    let Some(raw) = app_compose else {
        return Vec::new();
    };
    let parsed: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let compose = parsed
        .get("docker_compose_file")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if compose.is_empty() {
        return Vec::new();
    }
    // The OutLayer release version is the trailing `-<semver>` of the compose `name`, if present.
    let version = parsed
        .get("name")
        .and_then(|v| v.as_str())
        .and_then(parse_release_version);

    let mut rows: Vec<ImageRow> = Vec::new();
    // Track the current `services:` child key (the service/container name) as we descend lines.
    let mut current_service: Option<String> = None;
    let mut in_services = false;
    let mut services_indent: usize = 0;

    for line in compose.lines() {
        let trimmed = line.trim_start();
        // Skip comments and blanks for service/image detection.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();

        if !in_services {
            if trimmed.starts_with("services:") {
                in_services = true;
                services_indent = indent;
            }
            continue;
        }
        // A top-level key at or below the `services:` indent ends the services block.
        if indent <= services_indent && !trimmed.starts_with("services:") {
            in_services = false;
            current_service = None;
            continue;
        }
        // A service key: a deeper-than-`services:` mapping key ending in `:` with no inline value.
        if let Some(name) = service_key(trimmed) {
            current_service = Some(name);
            continue;
        }
        // An image line under the current service.
        if let Some(image_ref) = trimmed.strip_prefix("image:") {
            if let Some(row) = image_row(image_ref.trim(), current_service.as_deref(), version.as_deref()) {
                rows.push(row);
            }
        }
    }
    rows
}

/// A bare mapping key like `keystore:` (no inline value) → its name. Anything with an inline value
/// (`image: …`, `restart: …`) returns `None` so only service-name keys are captured.
fn service_key(trimmed: &str) -> Option<String> {
    let key = trimmed.strip_suffix(':')?;
    if key.is_empty() || key.contains(char::is_whitespace) || key.contains(':') || key.starts_with('-') {
        return None;
    }
    Some(key.to_string())
}

/// Build one `ImageRow` from an `image:` value of the form `<ref>@sha256:<hexdigest>`. Returns `None`
/// if the value carries no `@sha256:` digest (we only table digest-pinned images — the measured ones).
fn image_row(value: &str, service: Option<&str>, version: Option<&str>) -> Option<ImageRow> {
    let (image, digest_part) = value.split_once("@sha256:")?;
    let image = image.trim();
    let digest_hex = digest_part.trim();
    if image.is_empty() || digest_hex.is_empty() {
        return None;
    }
    let digest = format!("sha256:{digest_hex}");
    let sigstore_url = format!("https://search.sigstore.dev/?hash={digest}");

    // OutLayer-built images live under the `outlayer/` docker.io namespace; everything else (dstack
    // system images like `dstacktee/dstack-kms`, or a gateway image) is dstack-provided.
    let is_outlayer = image.contains("outlayer/near-outlayer");
    let (origin, release_url) = if is_outlayer {
        let url = version.map(|v| {
            format!("https://github.com/fastnear/near-outlayer/releases/tag/v{v}")
        });
        ("OutLayer-built", url)
    } else {
        ("dstack system image", None)
    };

    Some(ImageRow {
        container: service.unwrap_or(image).to_string(),
        image: image.to_string(),
        digest,
        sigstore_url,
        release_url,
        origin,
    })
}

/// Parse the trailing release version from a compose `name` like `outlayer-worker-testnet-0.1.35`
/// → `0.1.35`. Only a dotted-numeric trailing segment qualifies; `None` otherwise (e.g. `kms`).
fn parse_release_version(name: &str) -> Option<String> {
    let last = name.rsplit('-').next()?;
    if !last.is_empty()
        && last.contains('.')
        && last.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        Some(last.to_string())
    } else {
        None
    }
}

/// Flatten a `DecodedReport` (decoded straight from the verified quote) into the page's view block.
/// The register rows include the TDX-module fields Phala surfaces (mr_seam, tee_tcb_svn, …) plus the
/// 64-byte report_data. `fmspc` + `quote_hex` are kept separate for the verdict row / `<pre>` block.
fn decoded_report_view(d: &DecodedReport) -> DecodedReportView {
    let rows = vec![
        MeasurementRow { label: "mrtd", value: d.mrtd.clone() },
        MeasurementRow { label: "rtmr0", value: d.rtmr0.clone() },
        MeasurementRow { label: "rtmr1", value: d.rtmr1.clone() },
        MeasurementRow { label: "rtmr2", value: d.rtmr2.clone() },
        MeasurementRow { label: "rtmr3", value: d.rtmr3.clone() },
        MeasurementRow { label: "report_data", value: d.report_data.clone() },
        MeasurementRow { label: "mr_seam", value: d.mr_seam.clone() },
        MeasurementRow { label: "mr_signer_seam", value: d.mr_signer_seam.clone() },
        MeasurementRow { label: "tee_tcb_svn", value: d.tee_tcb_svn.clone() },
        MeasurementRow { label: "td_attributes", value: d.td_attributes.clone() },
        MeasurementRow { label: "xfam", value: d.xfam.clone() },
    ];
    DecodedReportView { rows, fmspc: d.fmspc.clone(), quote_hex: d.quote_hex.clone() }
}

/// Build a `VerdictView` from the matching `CvmVerdict`, or the "verifying…" pending state if none.
fn build_verdict(verdict: Option<&CvmVerdict>) -> VerdictView {
    let Some(v) = verdict else {
        return VerdictView {
            pending: true,
            sig_valid: false,
            tcb_status: None,
            tcb_class: "bad",
            measurements_match: None,
            on_chain: OnChain::NotApplicable,
            on_chain_contract: None,
            advisory_ids: Vec::new(),
            verify_error: None,
            failing: false, // not failing — just not done yet
        };
    };

    let on_chain = match v.on_chain_approved {
        Some(true) => OnChain::Approved,
        Some(false) => OnChain::NotApproved,
        None => OnChain::NotApplicable,
    };

    // The card goes loud/red if any concrete facet failed. Note: a *missing* on-chain result
    // (NotApplicable / RPC-unknown) is NOT itself a failure; only an explicit NOT-approved is.
    let failing = !v.sig_valid
        || on_chain.not_approved()
        || v.quote_measurements_match == Some(false)
        || v.error.is_some();

    VerdictView {
        pending: false,
        sig_valid: v.sig_valid,
        tcb_status: v.tcb_status.clone(),
        tcb_class: VerdictView::tcb_class_of(v.tcb_status.as_deref()),
        measurements_match: v.quote_measurements_match,
        on_chain,
        on_chain_contract: v.on_chain_contract.clone(),
        advisory_ids: v.advisory_ids.clone(),
        verify_error: v.error.clone(),
        failing,
    }
}

/// Collapse a CVM's verdict into the compact index `Summary`. Pending when no verdict exists yet;
/// Verified only when EVERY concrete check passes (signature, TCB UpToDate, on-chain approved-or-n/a,
/// measurements match); Failed otherwise. Mirrors the per-facet logic in `build_verdict` so the row
/// chip and the detail card can never disagree.
fn summary_of(verdict: Option<&CvmVerdict>) -> Summary {
    let Some(v) = verdict else {
        return Summary::Pending;
    };
    let on_chain_ok = !matches!(v.on_chain_approved, Some(false));
    let tcb_ok = v.tcb_status.as_deref() == Some("UpToDate");
    let measurements_ok = v.quote_measurements_match != Some(false);
    if v.sig_valid && tcb_ok && on_chain_ok && measurements_ok && v.error.is_none() {
        Summary::Verified
    } else {
        Summary::Failed
    }
}

/// Trim an obvious trailing instance-number suffix from a CVM name to get the app's display name:
/// `mainnet-worker-1` → `mainnet-worker`, `testnet-keystore-02` → `testnet-keystore`. Only a final
/// `-<digits>` segment is stripped, and only when something non-empty remains before it; anything
/// else (no suffix, or a name that is *only* digits) is returned unchanged. Conservative on purpose
/// — when in doubt we keep the full first-instance name (the count chip + detail page disambiguate).
fn app_display_name(name: &str) -> String {
    if let Some((head, tail)) = name.rsplit_once('-') {
        if !head.is_empty() && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return head.to_string();
        }
    }
    name.to_string()
}

/// Fold a group of instances' statuses into one display string. All-equal → that status verbatim;
/// otherwise a compact mixed indicator: "<R> running / <N>" when some are running, else "mixed".
/// Case-insensitive on "running" so `Running`/`running` both count. Never panics; `instances` is
/// always ≥ 1 here (a group exists because it has instances).
fn aggregate_status(statuses: &[&str]) -> String {
    let first = statuses.first().copied().unwrap_or("");
    if statuses.iter().all(|s| *s == first) {
        return first.to_string();
    }
    let running = statuses
        .iter()
        .filter(|s| s.eq_ignore_ascii_case("running"))
        .count();
    if running > 0 {
        format!("{running} running / {}", statuses.len())
    } else {
        "mixed".to_string()
    }
}

/// Build one compact index APP row from a group of CVM instances sharing one `app_id` (in their
/// node order — caller guarantees ≥ 1, all with the same `app_id`). Joins each instance with its
/// verdict (matched by `vm_id`), folds the per-instance summaries into the AGGREGATE chip, derives
/// a trimmed display name, the instance count, and the aggregate status.
fn build_app_row(instances: &[&CvmAttestation], verdicts: &[CvmVerdict]) -> AppRowView {
    // ≥ 1 by construction; fall back to a benign empty row only if a caller ever violates that.
    let Some(first) = instances.first() else {
        return AppRowView {
            name: String::new(),
            role_label: role_label(Role::Unknown),
            network_label: None,
            status: String::new(),
            instance_count: 0,
            multi_instance: false,
            app_id: String::new(),
            summary_class: Summary::Pending.class(),
            summary_label: Summary::Pending.label(),
        };
    };

    let summary = Summary::aggregate(instances.iter().map(|c| {
        let verdict = verdicts.iter().find(|v| v.vm_id == c.vm_id);
        summary_of(verdict)
    }));

    let statuses: Vec<&str> = instances.iter().map(|c| c.status.as_str()).collect();
    let count = instances.len();

    AppRowView {
        name: app_display_name(&first.name),
        role_label: role_label(first.role),
        network_label: first.network.clone(),
        status: aggregate_status(&statuses),
        instance_count: count,
        multi_instance: count > 1,
        app_id: first.app_id.clone(),
        summary_class: summary.class(),
        summary_label: summary.label(),
    }
}

/// Group a node's CVMs by `app_id`, preserving first-seen order of both the apps and the instances
/// within each app. Returns each distinct `app_id`'s instances as a borrowed slice-vec, ready for
/// `build_app_row`. Pure; no allocation of CVMs (only borrows).
fn group_by_app<'a>(cvms: &'a [CvmAttestation]) -> Vec<Vec<&'a CvmAttestation>> {
    let mut order: Vec<&str> = Vec::new();
    let mut groups: Vec<Vec<&'a CvmAttestation>> = Vec::new();
    for cvm in cvms {
        match order.iter().position(|id| *id == cvm.app_id.as_str()) {
            Some(idx) => groups[idx].push(cvm),
            None => {
                order.push(cvm.app_id.as_str());
                groups.push(vec![cvm]);
            }
        }
    }
    groups
}

/// Build one `CvmView`, joining the CVM with its verdict (matched by `vm_id`). `instance_index`
/// (1-based) and `instance_total` position this card among the instances sharing the `app_id` so the
/// detail page can label "instance N of M" when there's more than one.
fn build_cvm(
    cvm: &CvmAttestation,
    verdicts: &[CvmVerdict],
    instance_index: usize,
    instance_total: usize,
) -> CvmView {
    let verdict = verdicts.iter().find(|v| v.vm_id == cvm.vm_id);
    let decoded = verdict
        .and_then(|v| v.decoded.as_ref())
        .map(decoded_report_view);
    let kms_in_tee = cvm
        .key_provider
        .as_deref()
        .map(|k| k.eq_ignore_ascii_case("kms"))
        .unwrap_or(false);

    CvmView {
        name: cvm.name.clone(),
        role_label: role_label(cvm.role),
        network_label: cvm.network.clone(),
        status: cvm.status.clone(),
        uptime: cvm.uptime.clone(),
        app_id: cvm.app_id.clone(),
        vm_id: cvm.vm_id.clone(),
        instance_index,
        instance_total,
        kms_in_tee,
        gateway_domain: gateway_domain(cvm.role, &cvm.app_id),
        verdict: build_verdict(verdict),
        decoded,
        measurements: measurement_rows(cvm.measurements.as_ref()),
        app_compose: cvm.app_compose.clone(),
        image_digests: cvm.image_digests.clone(),
        images: image_rows(cvm.app_compose.as_deref()),
        os_version: cvm.os_version.clone(),
        os_image_hash: cvm.os_image_hash.clone(),
        mr_aggregated: cvm.mr_aggregated.clone(),
        compose_hash: cvm.compose_hash.clone(),
        key_provider: cvm.key_provider.clone(),
        collect_error: cvm.error.clone(),
    }
}

/// Build one `NodeListView` (compact index rows) from a stored report's parts: the node header
/// (id + freshness) plus one thin `AppRowView` per distinct `app_id` (instances sharing an app_id
/// collapse into a single row) for the list.
pub fn build_node_list(
    now: u64,
    received_at: u64,
    report: &NodeReport,
    verdicts: &[CvmVerdict],
) -> NodeListView {
    let rows = group_by_app(&report.cvms)
        .iter()
        .map(|group| build_app_row(group, verdicts))
        .collect();
    NodeListView {
        node_id: report.node_id.clone(),
        last_seen_human: humanize_age(now, received_at),
        last_seen_class: freshness(now, received_at).class(),
        rows,
    }
}

// ---------------------------------------------------------------------------------------------
// Templates.
// ---------------------------------------------------------------------------------------------

/// The `https://proof.t16z.com` quote-explorer link, shown per CVM as an independent cross-check.
const PROOF_EXPLORER_URL: &str = "https://proof.t16z.com";
/// dstack releases page — linked from the App OS section. The OS images are tagged in the
/// meta-dstack repo; the precise OS identity is the per-CVM `os_image_hash` + the dynamic
/// `os_version` tag (from `vm_config.image`), so this link is just the human-readable release index.
const DSTACK_RELEASES_URL: &str = "https://github.com/Dstack-TEE/meta-dstack/releases";

/// The index page — the compact LIST. askama compiles `templates/index.html` at build time; field
/// access there is auto-escaped.
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexPage {
    pub nodes: Vec<NodeListView>,
}

impl IndexPage {
    pub fn new(nodes: Vec<NodeListView>) -> Self {
        IndexPage { nodes }
    }

    /// Render to a `String`. Errors (should not happen for a compiled template) bubble up so the
    /// caller can turn them into a 500 instead of panicking on the request path.
    pub fn render_page(&self) -> Result<String, askama::Error> {
        self.render()
    }
}

/// The per-app DETAIL page — the full sectioned "verified aspects" view for every CVM sharing one
/// `app_id`. askama compiles `templates/app.html`; field access there is auto-escaped.
#[derive(Template)]
#[template(path = "app.html")]
pub struct AppDetailPage {
    /// The app_id this page is keyed by (echoed in the header, auto-escaped).
    pub app_id: String,
    /// Every CVM instance matching `app_id` (≥ 1 — multiple running instances can share one app_id,
    /// e.g. two worker instances; we render them all so nothing is hidden), each its own card.
    pub cvms: Vec<CvmView>,
    pub proof_explorer_url: &'static str,
    pub dstack_releases_url: &'static str,
}

impl AppDetailPage {
    pub fn new(app_id: String, cvms: Vec<CvmView>) -> Self {
        AppDetailPage {
            app_id,
            cvms,
            proof_explorer_url: PROOF_EXPLORER_URL,
            dstack_releases_url: DSTACK_RELEASES_URL,
        }
    }

    pub fn render_page(&self) -> Result<String, askama::Error> {
        self.render()
    }
}

/// The friendly "unknown app id" page (served with HTTP 404 by the handler). A tiny body + a link
/// back to `/` — never a panic/500. The unknown `app_id` is echoed back, auto-escaped.
#[derive(Template)]
#[template(path = "not_found.html")]
pub struct UnknownAppPage {
    pub app_id: String,
}

impl UnknownAppPage {
    pub fn render_page(&self) -> Result<String, askama::Error> {
        self.render()
    }
}

/// One stored node's renderable parts: when the portal received it, the report, and its per-CVM
/// verdicts. This is exactly what `main.rs`'s `StoredReport` carries (and what an offline render —
/// e.g. `examples/render_preview.rs` — assembles), borrowed so the caller keeps ownership.
pub struct StoredNode<'a> {
    pub received_at: u64,
    pub report: &'a NodeReport,
    pub verdicts: &'a [CvmVerdict],
}

/// Render the INDEX list: the compact one-row-per-APP (app_id-grouped) view of every stored node,
/// as of `now`.
///
/// Shared by the live `/` handler and offline tooling so a preview renders through the IDENTICAL
/// view-model build + template path the public page uses. Pure + side-effect-free: builds the view
/// model and renders; no IO, no panics.
pub fn render_index(now: u64, nodes: &[StoredNode<'_>]) -> Result<String, askama::Error> {
    let views: Vec<NodeListView> = nodes
        .iter()
        .map(|n| build_node_list(now, n.received_at, n.report, n.verdicts))
        .collect();
    IndexPage::new(views).render_page()
}

/// Render the per-app DETAIL page for `app_id`: the full sectioned layout for EVERY CVM instance
/// whose `app_id` matches, across all stored nodes (multiple running instances can share one app_id).
///
/// Returns `Ok(None)` when no CVM matches (unknown app id) so the caller can serve a friendly 404
/// rather than a 200-with-empty-page or a panic. Pure + side-effect-free; no IO, no panics on wire
/// values. An empty `app_id` path never matches (we never link to one), so it also yields `None`.
pub fn render_app(
    app_id: &str,
    now: u64,
    nodes: &[StoredNode<'_>],
) -> Result<Option<String>, askama::Error> {
    let _ = now; // detail page shows per-CVM aspects, not the freshness pill; kept for symmetry.
    if app_id.is_empty() {
        return Ok(None);
    }
    // Gather every matching CVM instance across all nodes, joined with its verdict. Stable order:
    // nodes are already sorted by the caller; we preserve their CVM order within each. Collect the
    // borrows first so we know the total before building (needed for the "instance N of M" label).
    let matches: Vec<(&CvmAttestation, &[CvmVerdict])> = nodes
        .iter()
        .flat_map(|n| {
            n.report
                .cvms
                .iter()
                .filter(|c| c.app_id == app_id)
                .map(move |c| (c, n.verdicts))
        })
        .collect();

    if matches.is_empty() {
        return Ok(None);
    }
    let total = matches.len();
    let cvms: Vec<CvmView> = matches
        .into_iter()
        .enumerate()
        .map(|(i, (c, verdicts))| build_cvm(c, verdicts, i + 1, total))
        .collect();
    AppDetailPage::new(app_id.to_string(), cvms)
        .render_page()
        .map(Some)
}

/// Render the friendly "unknown app id" body (paired with HTTP 404 at the handler). Never `None`.
pub fn render_unknown_app(app_id: &str) -> Result<String, askama::Error> {
    UnknownAppPage { app_id: app_id.to_string() }.render_page()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_shared::{CvmAttestation, Measurements, NodeReport, Role};

    fn sample_measurements() -> Measurements {
        Measurements {
            mrtd: "aa11".repeat(24),
            rtmr0: "bb22".repeat(24),
            rtmr1: "cc33".repeat(24),
            rtmr2: "dd44".repeat(24),
            rtmr3: "ee55".repeat(24),
        }
    }

    fn sample_cvm(name: &str) -> CvmAttestation {
        CvmAttestation {
            vm_id: "vm-1".to_string(),
            name: name.to_string(),
            role: Role::Worker,
            network: Some("mainnet".to_string()),
            status: "running".to_string(),
            uptime: Some("3d 4h".to_string()),
            app_id: "abc123app".to_string(),
            instance_id: None,
            compose_hash: Some("c0ffee".to_string()),
            device_id: None,
            mr_aggregated: Some("aggr-hash".to_string()),
            os_image_hash: Some("os-hash".to_string()),
            os_version: Some("dstack-0.5.11".to_string()),
            measurements: Some(sample_measurements()),
            image_digests: vec!["repo@sha256:deadbeef".to_string()],
            app_compose: None,
            key_provider: Some("kms".to_string()),
            app_cert_pem: None,
            event_log: Vec::new(),
            error: None,
        }
    }

    fn sample_decoded() -> DecodedReport {
        DecodedReport {
            mrtd: "11".repeat(48),
            rtmr0: "22".repeat(48),
            rtmr1: "33".repeat(48),
            rtmr2: "44".repeat(48),
            rtmr3: "55".repeat(48),
            report_data: "66".repeat(64),
            mr_seam: "77".repeat(48),
            mr_signer_seam: "88".repeat(48),
            tee_tcb_svn: "99".repeat(16),
            td_attributes: "0000001000000000".to_string(),
            xfam: "e702060000000000".to_string(),
            fmspc: Some("B0C06F000000".to_string()),
            quote_hex: "0400020081deadbeef".to_string(),
        }
    }

    fn approved_verdict() -> CvmVerdict {
        CvmVerdict {
            vm_id: "vm-1".to_string(),
            sig_valid: true,
            tcb_status: Some("UpToDate".to_string()),
            advisory_ids: Vec::new(),
            fmspc: Some("B0C06F000000".to_string()),
            decoded: Some(sample_decoded()),
            quote_measurements_match: Some(true),
            on_chain_approved: Some(true),
            on_chain_contract: Some("worker.outlayer.mainnet".to_string()),
            error: None,
            verified_at: 0,
        }
    }

    /// Build a one-node `StoredNode` set for the render-fn tests, given a report + verdicts. The
    /// borrowed pair must outlive the call, so callers hold `report`/`verdicts` in locals.
    fn stored<'a>(report: &'a NodeReport, verdicts: &'a [CvmVerdict]) -> Vec<StoredNode<'a>> {
        vec![StoredNode { received_at: 5, report, verdicts }]
    }

    /// A worker instance with a distinct `vm_id`/`name`, sharing `app_id == "abc123app"`. Used to
    /// build the multi-instance-per-app_id index/grouping tests.
    fn instance(vm_id: &str, name: &str) -> CvmAttestation {
        let mut c = sample_cvm(name);
        c.vm_id = vm_id.to_string();
        c
    }

    /// `approved_verdict` retargeted to `vm_id` so it matches a specific instance.
    fn verdict_for(vm_id: &str) -> CvmVerdict {
        CvmVerdict { vm_id: vm_id.to_string(), ..approved_verdict() }
    }

    // ----------------------------- INDEX (list) -----------------------------

    /// The index renders one compact row per CVM, links it to `/app/<app_id>`, and shows the green
    /// "✓ Verified" summary chip for an approved CVM (under its node header).
    #[test]
    fn index_lists_rows_with_link_and_verified_summary() {
        let report = NodeReport {
            node_id: "node-tdx-dal-2".to_string(),
            collected_at: 100,
            cvms: vec![sample_cvm("mainnet-worker-1")],
        };
        let verdicts = [approved_verdict()];
        let html = render_index(200, &stored(&report, &verdicts)).expect("render");

        // Node header + role + network present.
        assert!(html.contains("node-tdx-dal-2"), "node id missing");
        assert!(html.contains("Worker"), "role label missing");
        assert!(html.contains("mainnet"), "network badge missing");
        // The row links to the per-app detail page, keyed by app_id.
        assert!(
            html.contains("href=\"/app/abc123app\""),
            "row link to /app/<app_id> missing"
        );
        // Compact GREEN verdict summary for an approved CVM.
        assert!(html.contains("✓ Verified"), "compact Verified summary missing");
        // Freshness pill on the node header.
        assert!(html.contains("ago"), "freshness string missing");
        // Display name has the trailing instance-number suffix trimmed.
        assert!(html.contains("mainnet-worker"), "trimmed display name missing");
        // A single-instance app shows NO multi-instance count marker.
        assert!(
            !html.contains("instances"),
            "single-instance app must not show an 'N instances' marker"
        );
        // The list is light — no decoded quote / section headings leak into it.
        assert!(
            !html.contains("<h3>TDX Hardware"),
            "detail section heading leaked into the index list"
        );
        assert!(
            !html.contains("0400020081deadbeef"),
            "raw quote hex leaked into the index list"
        );
    }

    /// Two CVMs that SHARE one app_id collapse into ONE index row carrying a "2 instances" marker
    /// and a single link to `/app/<that app_id>` — not two rows, not two links.
    #[test]
    fn index_groups_instances_sharing_app_id_into_one_row() {
        let report = NodeReport {
            node_id: "node-tdx-dal-2".to_string(),
            collected_at: 0,
            cvms: vec![
                instance("vm-a", "mainnet-worker-1"),
                instance("vm-b", "mainnet-worker-2"),
            ],
        };
        let verdicts = [verdict_for("vm-a"), verdict_for("vm-b")];
        let html = render_index(10, &stored(&report, &verdicts)).expect("render");

        // Exactly ONE row link for the shared app_id (count the row-link anchors to /app/abc123app).
        assert_eq!(
            html.matches("href=\"/app/abc123app\"").count(),
            1,
            "two instances sharing one app_id must render exactly one index row/link"
        );
        // The multi-instance count marker is present and reads "2 instances".
        assert!(html.contains("2 instances"), "'2 instances' marker missing");
        // Both instances passed → aggregate is the green Verified chip.
        assert!(html.contains("✓ Verified"), "aggregate Verified chip missing");
        // The two distinct instance names do NOT both leak as separate rows — the row shows the
        // trimmed display name of the first instance.
        assert!(html.contains("mainnet-worker"), "display name missing");
    }

    /// The aggregate index chip is FAILING when ANY single instance fails (the other passes).
    #[test]
    fn index_aggregate_fails_if_one_instance_fails() {
        let report = NodeReport {
            node_id: "node-tdx-dal-2".to_string(),
            collected_at: 0,
            cvms: vec![
                instance("vm-a", "mainnet-worker-1"),
                instance("vm-b", "mainnet-worker-2"),
            ],
        };
        // vm-a passes; vm-b is NOT approved on-chain → fails.
        let mut bad = verdict_for("vm-b");
        bad.on_chain_approved = Some(false);
        let verdicts = [verdict_for("vm-a"), bad];
        let html = render_index(10, &stored(&report, &verdicts)).expect("render");

        assert!(
            html.contains("✗ Check failed"),
            "aggregate must fail when one instance fails"
        );
        assert!(
            !html.contains("✓ Verified"),
            "aggregate must not show Verified when one instance fails"
        );
        // Still a single grouped row with the count marker.
        assert_eq!(html.matches("href=\"/app/abc123app\"").count(), 1, "still one row");
        assert!(html.contains("2 instances"), "'2 instances' marker missing");
    }

    /// A failing verdict (e.g. NOT-approved on-chain) shows the red "✗ Check failed" row summary.
    #[test]
    fn index_shows_failed_summary() {
        let mut v = approved_verdict();
        v.on_chain_approved = Some(false);
        let report = NodeReport {
            node_id: "node-bad".to_string(),
            collected_at: 0,
            cvms: vec![sample_cvm("mainnet-worker-1")],
        };
        let verdicts = [v];
        let html = render_index(10, &stored(&report, &verdicts)).expect("render");
        assert!(html.contains("✗ Check failed"), "red Check-failed summary missing");
    }

    /// No verdict yet → the row shows the grey "verifying…" summary.
    #[test]
    fn index_shows_pending_summary() {
        let report = NodeReport {
            node_id: "node-pending".to_string(),
            collected_at: 0,
            cvms: vec![sample_cvm("testnet-keystore-1")],
        };
        let html = render_index(10, &stored(&report, &[])).expect("render");
        assert!(html.contains("verifying"), "pending summary not rendered");
    }

    /// A `<script>` injected into a CVM name MUST come out escaped on the INDEX list (auto-escaping,
    /// no XSS). The node id's injected tag is escaped too.
    #[test]
    fn index_escapes_injected_script_in_name() {
        let mut cvm = sample_cvm("<script>alert(1)</script>");
        cvm.network = None;
        let report = NodeReport {
            node_id: "n<script>".to_string(),
            collected_at: 0,
            cvms: vec![cvm],
        };
        let verdicts = [approved_verdict()];
        let html = render_index(10, &stored(&report, &verdicts)).expect("render");

        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw <script> from name leaked into the index — XSS!"
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "name not escaped");
        assert!(html.contains("n&lt;script&gt;"), "node id not escaped");
    }

    /// Empty report set → the friendly empty-state message.
    #[test]
    fn renders_empty_state() {
        let html = render_index(10, &[]).expect("render");
        assert!(
            html.to_lowercase().contains("no nodes"),
            "empty state message missing"
        );
    }

    // ----------------------------- DETAIL (/app/:app_id) -----------------------------

    /// The detail page for a known app_id carries the full section layout, the decoded quote, the
    /// on-chain "approved" marker, the honest disclaimer, the back-link, and the proof link.
    #[test]
    fn detail_renders_full_sections_for_known_app() {
        let report = NodeReport {
            node_id: "node-tdx-dal-2".to_string(),
            collected_at: 100,
            cvms: vec![sample_cvm("mainnet-worker-1")], // app_id == "abc123app"
        };
        let verdicts = [approved_verdict()];
        let html = render_app("abc123app", 200, &stored(&report, &verdicts))
            .expect("render")
            .expect("known app id should render Some");

        // Back-link to the list.
        assert!(html.contains("href=\"/\""), "back-link to / missing");
        assert!(html.contains("all workers"), "back-link label missing");
        // On-chain approval surfaced with the contract id.
        assert!(html.contains("approved"), "approval marker missing");
        assert!(html.contains("worker.outlayer.mainnet"), "contract id missing");
        // Honest verifier label — DCAP, never an affirmative ITA/Trust-Authority claim.
        assert!(html.contains("Intel DCAP"), "DCAP verifier label missing");
        assert!(!html.contains("ITA Certified"), "must not claim ITA Certified");
        assert!(
            !html.contains("Trust Authority Certified"),
            "must not claim Trust Authority certification"
        );
        assert!(
            html.contains("not Intel Trust Authority"),
            "honest 'not ITA' disclaimer missing"
        );
        // Decoded-from-quote fields (an rtmr + the fmspc) and the raw quote hex.
        assert!(html.contains(&"22".repeat(48)), "decoded rtmr0 hex missing");
        assert!(html.contains("B0C06F000000"), "fmspc missing");
        assert!(html.contains("0400020081deadbeef"), "raw quote hex missing");
        // Section headers from the Phala-style layout.
        assert!(html.contains("TDX Hardware"), "TDX hardware section missing");
        assert!(html.contains("Source Code"), "compose section missing");
        assert!(html.contains("Zero Trust Gateway"), "gateway section missing");
        assert!(html.contains("App OS"), "app-os section missing");
        // KMS / Root-of-Trust section (heading is "KMS — deploy-time key provisioning").
        assert!(html.contains("KMS — deploy-time key provisioning"), "kms section missing");
        // Computed gateway domain for a worker.
        assert!(
            html.contains("abc123app-8081.dstack.outlayer.ai"),
            "computed gateway domain missing"
        );
        // Independent-verify link present.
        assert!(html.contains("https://proof.t16z.com"), "proof link missing");
    }

    /// Multiple running instances can share one app_id — the detail page renders ALL of them (each
    /// its own card), even across different nodes.
    #[test]
    fn detail_renders_all_instances_sharing_app_id() {
        let mut a = sample_cvm("mainnet-worker-1");
        a.vm_id = "vm-a".to_string();
        let mut b = sample_cvm("mainnet-worker-2");
        b.vm_id = "vm-b".to_string();
        // Same app_id ("abc123app"), two nodes.
        let report_a = NodeReport { node_id: "node-1".to_string(), collected_at: 0, cvms: vec![a] };
        let report_b = NodeReport { node_id: "node-2".to_string(), collected_at: 0, cvms: vec![b] };
        let verdicts: [CvmVerdict; 0] = [];
        let nodes = vec![
            StoredNode { received_at: 5, report: &report_a, verdicts: &verdicts },
            StoredNode { received_at: 5, report: &report_b, verdicts: &verdicts },
        ];
        let html = render_app("abc123app", 10, &nodes)
            .expect("render")
            .expect("known app id should render Some");

        // Both instances' names appear, and there are two cards (count the article open tags, not
        // CSS selectors).
        assert!(html.contains("mainnet-worker-1"), "first instance missing");
        assert!(html.contains("mainnet-worker-2"), "second instance missing");
        assert_eq!(
            html.matches("<article class=\"card").count(),
            2,
            "expected two instance cards"
        );
        // Each card carries the per-instance "instance N of M" disambiguator and its vm_id.
        assert!(html.contains("instance 1 of 2"), "instance 1 of 2 marker missing");
        assert!(html.contains("instance 2 of 2"), "instance 2 of 2 marker missing");
        assert!(html.contains("vm-a"), "first vm_id missing");
        assert!(html.contains("vm-b"), "second vm_id missing");
    }

    /// A SINGLE-instance app detail page shows NO "instance N of M" marker (only multi-instance apps
    /// get the disambiguator).
    #[test]
    fn detail_single_instance_has_no_instance_marker() {
        let report = NodeReport {
            node_id: "node-1".to_string(),
            collected_at: 0,
            cvms: vec![sample_cvm("mainnet-worker-1")],
        };
        let verdicts = [approved_verdict()];
        let html = render_app("abc123app", 10, &stored(&report, &verdicts))
            .expect("render")
            .expect("Some");
        assert!(
            !html.contains("instance 1 of"),
            "single-instance app must not show an 'instance N of M' marker"
        );
    }

    /// A `<script>` injected into a CVM name OR app_compose MUST come out escaped on the DETAIL page
    /// — proves auto-escaping (no XSS) across both the header and the compose block.
    #[test]
    fn detail_escapes_injected_script_in_name_and_compose() {
        let mut cvm = sample_cvm("<script>alert(1)</script>");
        cvm.network = None;
        cvm.app_compose = Some("{\"x\":\"<script>steal()</script>\"}".to_string());
        let report = NodeReport {
            node_id: "n<script>".to_string(),
            collected_at: 0,
            cvms: vec![cvm],
        };
        let verdicts = [approved_verdict()];
        let html = render_app("abc123app", 10, &stored(&report, &verdicts))
            .expect("render")
            .expect("Some");

        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw <script> from name leaked into HTML — XSS!"
        );
        assert!(
            !html.contains("<script>steal()</script>"),
            "raw <script> from app_compose leaked into HTML — XSS!"
        );
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "name not escaped");
        assert!(html.contains("&lt;script&gt;steal()&lt;/script&gt;"), "compose not escaped");
    }

    /// An unknown app_id → `render_app` returns `None`, and the friendly-404 body has the
    /// "no worker found" message + a link back to `/` (and does NOT panic).
    #[test]
    fn unknown_app_id_returns_none_then_friendly_404_body() {
        let report = NodeReport {
            node_id: "node-1".to_string(),
            collected_at: 0,
            cvms: vec![sample_cvm("mainnet-worker-1")], // app_id == "abc123app"
        };
        let verdicts = [approved_verdict()];
        let out = render_app("does-not-exist", 10, &stored(&report, &verdicts)).expect("render");
        assert!(out.is_none(), "unknown app id must yield None (handler maps to 404)");

        // An empty app_id never matches either.
        assert!(
            render_app("", 10, &stored(&report, &verdicts)).expect("render").is_none(),
            "empty app id must yield None"
        );

        // The friendly-404 body renders, names the missing id (escaped), and links back to /.
        let body = render_unknown_app("does-not-exist").expect("render 404 body");
        assert!(
            body.to_lowercase().contains("no worker found"),
            "friendly-404 message missing"
        );
        assert!(body.contains("does-not-exist"), "missing app id not echoed");
        assert!(body.contains("href=\"/\""), "404 back-link to / missing");
    }

    /// `summary_of` collapses the per-facet verdict into the right tri-state.
    #[test]
    fn summary_tri_state() {
        let v = approved_verdict();
        assert_eq!(summary_of(Some(&v)), Summary::Verified);
        assert_eq!(summary_of(None), Summary::Pending);

        let mut bad_sig = approved_verdict();
        bad_sig.sig_valid = false;
        assert_eq!(summary_of(Some(&bad_sig)), Summary::Failed);

        let mut not_approved = approved_verdict();
        not_approved.on_chain_approved = Some(false);
        assert_eq!(summary_of(Some(&not_approved)), Summary::Failed);

        let mut stale_tcb = approved_verdict();
        stale_tcb.tcb_status = Some("OutOfDate".to_string());
        assert_eq!(summary_of(Some(&stale_tcb)), Summary::Failed);

        // n/a on-chain (kms/gateway) is NOT a failure on its own.
        let mut na = approved_verdict();
        na.on_chain_approved = None;
        na.on_chain_contract = None;
        assert_eq!(summary_of(Some(&na)), Summary::Verified);
    }

    /// `Summary::aggregate` folds a group with Failed dominating, then Pending, then Verified.
    #[test]
    fn summary_aggregate_folds_with_failed_dominating() {
        use Summary::*;
        // Any Failed → Failed, regardless of the rest.
        assert_eq!(Summary::aggregate([Verified, Failed, Pending]), Failed);
        assert_eq!(Summary::aggregate([Failed, Verified]), Failed);
        // No Failed but some Pending → Pending.
        assert_eq!(Summary::aggregate([Verified, Pending]), Pending);
        // All Verified → Verified.
        assert_eq!(Summary::aggregate([Verified, Verified]), Verified);
        assert_eq!(Summary::aggregate([Verified]), Verified);
        // Empty (never a real app row) → Pending.
        assert_eq!(Summary::aggregate(std::iter::empty()), Pending);
    }

    /// `app_display_name` trims only an obvious trailing `-<digits>` instance suffix.
    #[test]
    fn app_display_name_trims_instance_suffix() {
        assert_eq!(app_display_name("mainnet-worker-1"), "mainnet-worker");
        assert_eq!(app_display_name("testnet-keystore-02"), "testnet-keystore");
        // No numeric suffix → unchanged.
        assert_eq!(app_display_name("dstack-gateway"), "dstack-gateway");
        assert_eq!(app_display_name("kms"), "kms");
        // A name that is only digits, or only a suffix, is kept intact (nothing meaningful remains).
        assert_eq!(app_display_name("42"), "42");
        assert_eq!(app_display_name("-1"), "-1");
    }

    /// `aggregate_status` shows the shared status when all agree, else a compact mixed indicator.
    #[test]
    fn aggregate_status_collapses_or_marks_mixed() {
        assert_eq!(aggregate_status(&["running", "running"]), "running");
        assert_eq!(aggregate_status(&["running"]), "running");
        assert_eq!(aggregate_status(&["running", "exited"]), "1 running / 2");
        assert_eq!(aggregate_status(&["exited", "stopped"]), "mixed");
    }

    /// An older agent that doesn't carry `app_compose` must degrade gracefully on the detail page.
    #[test]
    fn detail_compose_not_reported_degrades() {
        let report = NodeReport {
            node_id: "node-old-agent".to_string(),
            collected_at: 0,
            cvms: vec![sample_cvm("mainnet-worker-1")], // app_compose: None
        };
        let verdicts = [approved_verdict()];
        let html = render_app("abc123app", 10, &stored(&report, &verdicts))
            .expect("render")
            .expect("Some");
        assert!(
            html.contains("compose not reported yet"),
            "graceful compose-missing message absent"
        );
    }

    /// A reported app_compose is shown (its content appears) in the detail Source Code section.
    #[test]
    fn detail_renders_app_compose() {
        let mut cvm = sample_cvm("mainnet-worker-1");
        cvm.app_compose = Some("{\"docker_compose_file\":\"services: {}\"}".to_string());
        let report = NodeReport {
            node_id: "node-compose".to_string(),
            collected_at: 0,
            cvms: vec![cvm],
        };
        let verdicts = [approved_verdict()];
        let html = render_app("abc123app", 10, &stored(&report, &verdicts))
            .expect("render")
            .expect("Some");
        assert!(html.contains("docker_compose_file"), "compose content missing");
    }

    /// A NOT-approved on-chain result flips the detail verdict card to failing + the loud marker.
    #[test]
    fn detail_not_approved_is_failing() {
        let mut v = approved_verdict();
        v.on_chain_approved = Some(false);
        let report = NodeReport {
            node_id: "node-bad".to_string(),
            collected_at: 0,
            cvms: vec![sample_cvm("mainnet-worker-1")],
        };
        let verdicts = [v];
        let html = render_app("abc123app", 10, &stored(&report, &verdicts))
            .expect("render")
            .expect("Some");
        assert!(html.contains("NOT approved"), "loud not-approved marker missing");
    }

    /// A realistic app-compose (OutLayer worker) → the Sigstore image table parses one OutLayer row
    /// with the right image, digest, Sigstore verify link, and a release link from the compose name.
    fn worker_app_compose() -> String {
        serde_json::json!({
            "name": "outlayer-worker-testnet-0.1.35",
            "docker_compose_file":
                "# header comment\nservices:\n  worker:\n    image: docker.io/outlayer/near-outlayer-worker@sha256:f12c9a981e886fab5cb53709ed35247318531dc4c3abdfa93effbb5e4ffe94bf\n    restart: on-failure:5\n"
        })
        .to_string()
    }

    #[test]
    fn image_table_parses_outlayer_image() {
        let rows = image_rows(Some(&worker_app_compose()));
        assert_eq!(rows.len(), 1, "expected exactly one image row");
        let r = &rows[0];
        assert_eq!(r.container, "worker");
        assert_eq!(r.image, "docker.io/outlayer/near-outlayer-worker");
        assert_eq!(
            r.digest,
            "sha256:f12c9a981e886fab5cb53709ed35247318531dc4c3abdfa93effbb5e4ffe94bf"
        );
        assert_eq!(
            r.sigstore_url,
            "https://search.sigstore.dev/?hash=sha256:f12c9a981e886fab5cb53709ed35247318531dc4c3abdfa93effbb5e4ffe94bf"
        );
        assert_eq!(
            r.release_url.as_deref(),
            Some("https://github.com/fastnear/near-outlayer/releases/tag/v0.1.35")
        );
        assert_eq!(r.origin, "OutLayer-built");
    }

    #[test]
    fn image_table_marks_non_outlayer_as_system_image() {
        let compose = serde_json::json!({
            "name": "kms",
            "docker_compose_file":
                "services:\n  kms:\n    image: dstacktee/dstack-kms@sha256:84b793feed825a5b5e70d04386e931e0e110461492793f17ab2128e39808d989\n"
        })
        .to_string();
        let rows = image_rows(Some(&compose));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].origin, "dstack system image");
        assert!(rows[0].release_url.is_none(), "system image must not get a release link");
        assert!(rows[0].digest.starts_with("sha256:"));
    }

    #[test]
    fn parse_release_version_only_dotted_numeric() {
        assert_eq!(
            parse_release_version("outlayer-worker-testnet-0.1.35").as_deref(),
            Some("0.1.35")
        );
        assert_eq!(parse_release_version("kms"), None);
        assert_eq!(parse_release_version("dstack-gateway"), None);
    }

    /// The rendered DETAIL page must avoid Phala / PCCS / dcap-qvl naming (de-Phala'd to Intel-direct
    /// copy) and MUST carry the Sigstore verify link + a measured digest in the source-code table.
    #[test]
    fn page_is_intel_direct_and_has_sigstore_table() {
        let mut cvm = sample_cvm("testnet-worker-1");
        cvm.app_compose = Some(worker_app_compose());
        cvm.os_version = Some("dstack-0.5.11".to_string());
        let report = NodeReport {
            node_id: "node-tdx-dal-2".to_string(),
            collected_at: 0,
            cvms: vec![cvm],
        };
        let verdicts = [approved_verdict()];
        let html = render_app("abc123app", 10, &stored(&report, &verdicts))
            .expect("render")
            .expect("Some");

        // De-Phala: no Phala / PCCS / dcap-qvl in the RENDERED output.
        assert!(!html.contains("Phala"), "rendered page must not name Phala");
        assert!(!html.contains("PCCS"), "rendered page must not name PCCS");
        assert!(!html.contains("dcap-qvl"), "rendered page must not name dcap-qvl");
        // Intel-direct framing present.
        assert!(html.contains("Intel's PCS"), "Intel PCS framing missing");
        assert!(
            html.contains("not Intel Trust Authority"),
            "honest 'not ITA' disclaimer missing"
        );
        // Sigstore verify link + a measured digest.
        assert!(
            html.contains("https://search.sigstore.dev/?hash=sha256:"),
            "sigstore verify link missing"
        );
        assert!(
            html.contains("sha256:f12c9a981e886fab5cb53709ed35247318531dc4c3abdfa93effbb5e4ffe94bf"),
            "measured digest missing from table"
        );
        // The release link for an OutLayer image.
        assert!(
            html.contains("https://github.com/fastnear/near-outlayer/releases/tag/v0.1.35"),
            "release link missing"
        );
        // Dynamic OS version rendered (no hardcoded label).
        assert!(html.contains("dstack-0.5.11"), "dynamic os_version missing");
        assert!(html.contains("os_version"), "os_version row label missing");
    }

    #[test]
    fn gateway_domain_by_role() {
        assert_eq!(
            gateway_domain(Role::Keystore, "appid"),
            Some("appid-8081.dstack.outlayer.ai".to_string())
        );
        assert_eq!(
            gateway_domain(Role::Worker, "appid"),
            Some("appid-8081.dstack.outlayer.ai".to_string())
        );
        assert_eq!(gateway_domain(Role::Kms, "appid"), None);
        assert_eq!(gateway_domain(Role::Gateway, "appid"), None);
        assert_eq!(gateway_domain(Role::Worker, ""), None);
    }

    #[test]
    fn freshness_buckets() {
        assert_eq!(freshness(1000, 999), Freshness::Live);
        assert_eq!(freshness(1000, 400), Freshness::Stale);
        assert_eq!(freshness(10_000, 0), Freshness::Dead);
    }

    #[test]
    fn humanize_age_units() {
        assert_eq!(humanize_age(100, 99), "just now");
        assert_eq!(humanize_age(100, 70), "30s ago");
        assert_eq!(humanize_age(1000, 400), "10m ago");
        assert_eq!(humanize_age(10_000, 0), "2h ago");
        assert_eq!(humanize_age(200_000, 0), "2d ago");
    }
}
