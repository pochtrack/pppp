# Vault exposure — HackerOne submission

## Before you submit (do NOT paste this section)
- **Dedup-search** the program for: "Vault", "exposed", "version disclosure", "sys/health". If a similar report
  exists, skip or reference it.
- **Re-run the curls from your own machine** so the traffic ties to your H1 handle (I ran them from a cloud host).
- **Do NOT run the CVE-2024-5798 auth-bypass against the live host** — that is unauthorized exploitation of a
  production secrets manager and will hurt you, not help. If you want to prove the CVE, do it in a **local lab** on
  Vault 1.16.2 and attach that PoC. The report below is written to stand on the read-only exposure evidence alone.
- Realistic severity: **Low–Medium**. It may be accepted as a hardening/info-disclosure issue or closed
  by-design/known. That's normal for this class.

---

## ⤵ PASTE FROM HERE INTO HACKERONE

**Title:** Internet-exposed HashiCorp Vault (production secrets manager) on `vault.algolia.net` — unauthenticated information disclosure + outdated version with known auth-bypass CVE (CVE-2024-5798)

**Asset:** `vault.algolia.net` (in scope: `*.algolia.net`)
**Weakness:** CWE-668 Exposure of Resource to Wrong Sphere / CWE-200 Information Disclosure / CWE-1104 Use of Unmaintained Component
**Severity (self-assessed):** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)

### Summary
`vault.algolia.net` exposes a production HashiCorp Vault cluster to the public internet. Its unauthenticated
system endpoints respond `200` from any host and disclose the exact version (**Vault 1.16.2**, OSS), an internal
hostname, HA/raft state, and the enabled authentication backend (**Okta OIDC**). Version 1.16.2 is missing the fix
for **CVE-2024-5798** (HCSEC-2024-11), an authentication-bypass in Vault's JWT/OIDC auth method, so the vulnerable
component is enabled on an internet-reachable, unpatched instance. A secrets-management service should not be
reachable from the public internet and should be patched.

### Steps to reproduce (all unauthenticated, read-only)
```bash
# 1. Version + reachability
curl -s https://vault.algolia.net/v1/sys/health
#   200 -> {"initialized":true,"sealed":false,...,"version":"1.16.2","enterprise":false,
#           "cluster_name":"vault-cluster-0d3c6369","cluster_id":"9075ba06-..."}

curl -s https://vault.algolia.net/v1/sys/seal-status
#   200 -> {"type":"shamir","initialized":true,"sealed":false,"t":2,"n":18,"version":"1.16.2",
#           "build_date":"2024-04-22T16:25:54Z","storage_type":"raft",...}

# 2. Internal hostname + HA/raft disclosure
curl -s https://vault.algolia.net/v1/sys/leader
#   200 -> {"ha_enabled":true,"is_self":true,
#           "leader_address":"http://hashicorp-vault-02.algolia.internal:8200",
#           "leader_cluster_address":"https://hashicorp-vault-02.algolia.internal:8201",
#           "raft_committed_index":...,"raft_applied_index":...}

# 3. Unauthenticated auth-method enumeration
curl -s https://vault.algolia.net/v1/sys/internal/ui/mounts
#   200 -> {"data":{"auth":{"oidc/":{"description":"Okta OIDC","type":"oidc"}},"secret":{}},...}

# 4. OIDC provider enabled (issuer + public JWKS)
curl -s https://vault.algolia.net/v1/identity/oidc/.well-known/openid-configuration
#   200 -> {"issuer":"https://vault.algolia.net/v1/identity/oidc",...}
```
All four return `200` with no authentication. (`/v1/sys/ha-status`, `/v1/sys/internal/ui/resultant-acl`,
`/v1/sys/metrics` correctly returned permission-denied/404 — so the exposure is scoped to unauth-by-design
endpoints, but those still leak the data above.)

### Impact
1. A production Vault (secrets manager) is reachable from the public internet — the full API surface, including
   `/v1/auth/oidc/*` login endpoints, is not restricted to an internal network/VPN/mTLS.
2. The exact version **1.16.2** is disclosed and is missing **CVE-2024-5798 / HCSEC-2024-11** (fixed in
   1.15.9 / 1.16.3 / 1.17.0): Vault's JWT/OIDC auth method did not correctly validate the role-bound audience
   (`aud`) claim for array-type audiences, so a JWT with a mismatched audience could authenticate when it should be
   rejected. The vulnerable `oidc/` backend is confirmed enabled. (Direct exploitability depends on the role's
   `bound_audiences`/`role_type` config and was NOT tested — reporting the exposed, unpatched, enabled component.)
3. Additional disclosure: internal hostname `hashicorp-vault-02.algolia.internal` (+ ports 8200/8201), unseal
   quorum (`t:2,n:18`), storage backend (raft), cluster id/name, build date, and the Okta OIDC auth topology.

### Remediation
- Restrict `vault.algolia.net` to internal networks / VPN / IP-allowlist, or require mTLS at the edge — do not
  serve the Vault API to the public internet (health checks can reach the LB without exposing the API).
- Upgrade Vault to a current patched release; prioritized because the CVE-2024-5798-affected OIDC/JWT backend is
  enabled.
- Review the OIDC role config (`bound_audiences`, `bound_claims`) to enforce strict audience validation.

### Testing notes
All testing was unauthenticated, read-only, non-destructive, and limited to documented monitoring endpoints on an
in-scope asset. No authentication attempts, no exploitation of CVE-2024-5798, no writes.

## ⤴ PASTE TO HERE

---
_Generated by [Claude Code](https://claude.ai/code)_
