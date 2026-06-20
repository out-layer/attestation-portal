# attestation-portal

Public TEE-attestation portal for the OutLayer self-hosted Intel TDX fleet. Serves `workers.outlayer.ai`
("prove our TEEs are genuine"). One operator may run several TDX servers.

**Logs / admin are intentionally NOT here (v1).** Operators read logs over SSH (`worker-ctl.sh logs`).
A future read-only web log viewer — reached over a node-initiated tunnel so the portal never gains
access INTO a TDX host — is designed in [docs/future-admin-logs.md](docs/future-admin-logs.md); build
it only if/when SSH gets inconvenient.

## Why a separate Rust service

Honest attestation needs the Intel-signature check on each TDX quote — that is `dcap-qvl`, a Rust
crate. The existing Next.js dashboard can only decode RTMR3 client-side; it cannot verify the quote.
So the verifying server is Rust, and the per-node collector shares its types.

## Security model — push, never pull

The TDX hosts run the crown jewels (keystore, gateway, MPC validator). The portal sits on a more
exposed box (next to the coordinator). So data flows **outbound from the node only** — the portal
NEVER reaches INTO a TDX host:

```
TDX node                                   portal (next to coordinator)        Cloudflare
  agent ──(collect vmm Status + per-CVM    │                                   │
          guest-agent Info, loopback)      │                                   │
        ──OUTBOUND POST /ingest (bearer)──▶ server ──stores latest per node──▶ workers.outlayer.ai
                                           └─ GET /api/attestation (public, read-only)  (via CF Tunnel)
```

A compromise of the portal yields only public attestation data + the ability to push fake reports
(which on-chain / quote verification detects) — and **zero** path or credential to a TDX host. See
[SECURITY.md](SECURITY.md).

## Crates

| crate | role |
|---|---|
| `shared` | wire types (`NodeReport`, `CvmAttestation`, `Measurements`, …) |
| `agent` | **per-node, read-only, outbound-only.** Runs on each TDX host as the vmm-owning user. Collects the VM list + each CVM's loopback guest-agent `Info`, normalizes it, and **POSTs** it to the portal's `/ingest` every `PUSH_INTERVAL_SECS`. Holds no secrets (the push token is low-stakes — the data is public), takes no control actions. Also serves a loopback-only `/attestation` + `/healthz` for on-node debugging. |
| `server` | receives bearer-authed pushes at `POST /ingest` (fails closed with no token), stores the latest report per node in memory, serves it read-only at `GET /api/attestation`. No fan-out, no SSRF surface. dcap-qvl quote verification + on-chain cross-check + the askama public page land in following phases. |

## Run

agent (on a TDX host, as the vmm-owning user — needs to read `/proc/<pid>/cmdline` of the qemu CVMs):
```bash
VMM_RPC=http://127.0.0.1:11000 NODE_ID=node-tdx-dal-2 \
  PORTAL_INGEST_URL=https://workers.outlayer.ai/ingest PUSH_TOKEN=<token> PUSH_INTERVAL_SECS=30 \
  AGENT_BIND=127.0.0.1:9300 \
  cargo run -p attestation-agent
# local debug (loopback): curl -s http://127.0.0.1:9300/attestation | jq
```

server (next to the coordinator; fronted by a CF Tunnel for `workers.outlayer.ai`):
```bash
SERVER_BIND=127.0.0.1:8088 INGEST_TOKEN=<same token> cargo run -p attestation-server
curl -s http://127.0.0.1:8088/api/attestation | jq
```

Design + data-source reference: `~/.claude/plans/outlayer-attestation-page-design.md`.
