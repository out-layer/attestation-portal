# Security model — attestation-portal

Reliability + security are the **top priority** of this project. The portal exists to PROVE our TEEs
are genuine; a vulnerability here voids that proof. The `/admin` surface touches a fleet of TDX hosts —
a compromise there could compromise the whole system. **This file is the security contract every change
must satisfy.** Closing ports is necessary but secondary: code quality is what protects us.

## Trust boundaries

- **agent** (one per TDX host): read-only collector. Holds NO secrets, performs NO control actions,
  binds to a **private interface only** (WireGuard/Tailscale/loopback — never `0.0.0.0`). Worst case if
  fully compromised: an attacker reads already-public attestation data. It must STAY that minimal — no
  command execution, no write paths, no secret access, no control RPC.
- **server / public page**: read-only, anonymous, holds no secrets. Renders attestation + verification.
- **server / `/admin`**: authenticated; **read-only in v1** (status + logs only — NO
  start/stop/deploy/restart). Even authenticated, it must not mutate the fleet or run arbitrary commands.

Public page and `/admin` should be **separable** (distinct binaries and/or network exposure) so a bug
in the public surface cannot reach the admin surface.

## Hard requirements (every change must hold)

1. **No shell / command injection.** Never interpolate ANY external input into a shell command. Invoke
   `worker-ctl.sh` / `vmm-cli` only with fixed, hard-coded argument vectors — no `sh -c`, no string
   concatenation, no user-influenced args. Prefer parsing the vmm RPC directly over shelling out.
2. **No SSRF / fan-out abuse.** The set of node endpoints the server contacts is **operator config
   only**, never request-derived. The server never fetches a URL chosen by a request.
3. **`/admin` auth.** Not naked basic-auth on the public internet. Require: TLS; a strong credential
   compared in **constant time**; rate-limiting + lockout; and ideally mTLS or an IP-allowlist / VPN in
   front. No default or blank credentials. Fail closed (no auth configured → admin disabled, not open).
4. **Read-only admin (v1).** No endpoint performs a control action on a CVM/host. If control is ever
   added, it is a separate, separately-hardened design — not slipped into v1.
5. **No secrets / internal topology in responses or logs.** Attestation data is public; never surface
   env, keys, tokens, `.sys-config`, internal-service private IPs, or auth material. Redact by
   allow-list (emit only known-safe fields), not by denylist.
6. **Minimal attack surface.** Few, vetted dependencies; bounded request bodies; strict connect/read
   timeouts; reject malformed input early; no dynamic code paths; no debug endpoints in release.
7. **Defense in depth.** Assume any single layer fails: the agent is private-bound AND read-only AND
   secretless; `/admin` is authed AND read-only AND not internet-exposed; the public page has no secret
   access at all. A compromise of one agent must not escalate to anything beyond public data.
8. **Verify.** Security-relevant logic ships with tests. The threat model is revisited whenever the
   surface changes. `cargo audit` / `cargo deny` in CI.

## Threats explicitly in scope

| Threat | Mitigation |
|---|---|
| Admin auth bypass / weak auth → fleet visibility (or control, if ever added) | req 3, 4 |
| Command injection via worker-ctl/vmm-cli → host RCE | req 1 |
| SSRF via node-endpoint / URL handling → internal-network probing | req 2 |
| Info disclosure (secrets, internal topology) via public page or logs | req 5 |
| Compromise of one agent → must not escalate | trust boundary, req 7 |
| Dependency / supply-chain vuln | req 6, 8 |
