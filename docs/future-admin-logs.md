# Future: read-only web logs / admin (deferred — design only)

**Status: NOT built. v1 ships attestation push only; operators read logs over SSH (`worker-ctl.sh
logs`).** This documents the design to add a read-only web log viewer LATER, if/when SSH gets
inconvenient — without weakening the security posture. Do not build it until there is a real need.

## The problem (why logs are the hard part)

Attestation data is public + slowly-changing, so the agent simply **pushes** it outbound — trivial and
safe. Logs are different: higher volume, **sensitive** (can contain secrets / internal detail / user
data), and wanted **on-demand** (an operator looks when debugging). Putting logs in a browser means the
log data must leave the node. There are two unsafe ways and one clean way:

- ❌ **Pull `portal → node`** — the portal reaches INTO a TDX host to fetch logs. This is the exact
  dangerous direction we forbid: the portal is a more-exposed box; any path/credential from it to a
  crown-jewel host (keystore / gateway / MPC validator) is a pivot. Rejected.
- ❌ **Push / cache logs on the portal** — stream all logs up and store them. Now sensitive logs sit on
  the more-exposed box (a juicy target) and are retained. Fine for *attestation* (public); **not** for
  logs. Rejected.
- ✅ **Node-initiated tunnel + on-demand read-only proxy** — see below.

## The clean design

The TDX node runs an **outbound** tunnel (e.g. `cloudflared`). The agent exposes read-only endpoints.
The portal / Cloudflare reaches them **on-demand through the node-initiated tunnel** — the node never
opens an inbound port and never grants shell. Logs are **proxied, never cached** on the portal.

```
operator ──▶ workers.outlayer.ai/admin ──(CF Access: SSO/allowlist/MFA)──▶ portal /admin (read-only UI)
                                                                              │  on demand, per request
TDX node:  cloudflared ──OUTBOUND tunnel──▶ Cloudflare ◀── portal asks ──────┘
   agent  (read-only):  GET /logs/<cvm>  (streams `worker-ctl.sh logs`, FIXED args)
                        GET /status      (vmm Status / worker-ctl status)
```

What a portal/CF compromise can do in the worst case: **read logs** (info disclosure) — bounded, and
auditable. What it CANNOT do: get a shell, run control actions, take the node, or read secrets the
agent doesn't expose. No inbound port on the node; no log hoard on the portal.

## Security requirements (must hold — see SECURITY.md)

1. **Read-only.** The agent exposes only log/status reads. No control endpoints (start/stop/deploy).
2. **No command injection.** `/logs/<cvm>` maps `<cvm>` to a FIXED allow-list of CVM names → fixed
   `worker-ctl.sh` arg vectors. Never interpolate the path/query into a shell. (SECURITY.md req 1.)
3. **No inbound port on the node.** The tunnel is node-initiated outbound only; the agent's log
   endpoints bind loopback and are reachable solely through the tunnel.
4. **`/admin` is authed + not naked.** CF Access (SSO / email allow-list / MFA) in front; the portal's
   `/admin` is separate from the public page and never internet-exposed without that gate.
5. **Logs proxied, never persisted** on the portal. Stream through; no disk, no cache, redact known
   secret patterns on the way out (allow-list of safe fields where feasible).
6. **Redaction + bounds.** Cap stream duration / line count; strip obvious secrets; rate-limit.

## Implementation sketch (when built)

- **agent**: add `cloudflared` (or equivalent) as a sidecar/systemd unit doing an outbound tunnel; add
  read-only `GET /logs/<cvm>` (chunked/SSE, streaming `worker-ctl.sh logs <fixed-name>`) + `GET /status`.
  Keep the existing attestation push unchanged. The CVM name comes ONLY from a hard-coded enum.
- **server**: add a SEPARATE `/admin` surface (ideally a distinct bind / distinct binary) gated by CF
  Access; it proxies the operator's on-demand log/status request to the node's agent through the
  tunnel and streams the result back without storing it. Attestation may stay cached (public); logs
  never.
- **Cloudflare**: a Tunnel per node (or one with per-node routes); CF Access policy on `/admin`.

## Why deferred

Operators already have SSH + `worker-ctl.sh logs` — a real, audited, least-privilege log path. A web
viewer is convenience, not necessity, and it adds attack surface (the agent now runs subprocesses; a
tunnel daemon; an authed admin surface). Ship the attestation product first; add this only when the
SSH workflow genuinely costs more than the added surface is worth.
