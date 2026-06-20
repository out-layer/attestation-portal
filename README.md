# attestation-portal

Public TEE-attestation portal + authenticated admin for the OutLayer self-hosted Intel TDX fleet.
Serves `workers.outlayer.ai` (public, "prove our TEEs are genuine") and `workers.outlayer.ai/admin`
(operator status, behind auth). One operator may run several TDX servers (an array of node IPs).

## Why a separate Rust service

Honest attestation needs the Intel-signature check on each TDX quote — that is `dcap-qvl`, a Rust
crate. The existing Next.js dashboard can only decode RTMR3 client-side; it cannot verify the quote.
So the verifying server is Rust, and the per-node collector + admin share its types.

## Crates

| crate | role |
|---|---|
| `shared` | wire types shared by agent + server (`NodeReport`, `CvmAttestation`, `Measurements`, …) |
| `agent` | **per-node, read-only.** Runs on each TDX host as the vmm-owning user. Queries the local dstack vmm for the VM list + each CVM's loopback guest-agent `Info`, normalizes it, serves JSON at `GET /attestation`. Holds no secrets, takes no control actions. |
| `server` *(next)* | central aggregator: fans out to each node's agent (array of IPs), runs `dcap-qvl` verify, calls the NEAR on-chain view methods, renders the public page (askama) + `/admin` (auth). |

## Architecture

```
workers.outlayer.ai  ──(server: axum + askama + dcap-qvl + NEAR RPC)
   ├─ fan-out to each node ─> http://<node-private>:9300/attestation   (agent, per host)
   │                                └─ vmm Status + per-CVM guest-agent Info (loopback only)
   └─ off-host directly ────> gateway :9202 AcmeInfo, KMS :11001 GetMeta, NEAR view methods
```

Loopback-only data (per-CVM `Info`, vmm RPC) is reachable only on each host → the agent runs there.
Off-host data (gateway AcmeInfo, KMS GetMeta) + on-chain checks the server does itself.

## agent — run

```bash
# on a TDX host, as the vmm-owning user (needs to read /proc/<pid>/cmdline of the qemu CVMs)
VMM_RPC=http://127.0.0.1:11000 AGENT_BIND=127.0.0.1:9300 NODE_ID=node-tdx-dal-2 \
  cargo run -p attestation-agent
curl -s http://127.0.0.1:9300/attestation | jq
```

Bind it to a private/WireGuard interface (not `0.0.0.0`) — it exposes attestation data, not secrets,
but there is no reason to publish it directly; the central server reaches it over the private mesh.

Design + data-source reference: `~/.claude/plans/outlayer-attestation-page-design.md`.
