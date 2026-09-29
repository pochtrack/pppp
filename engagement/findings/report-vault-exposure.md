# Vault exposure — HackerOne submission

## Before you submit (do NOT paste this section)
- **Dedup-search** the program for: "Vault", "exposed", "version disclosure", "sys/health". If similar exists, skip.
- **Re-run the curls from your own machine** so the traffic ties to your H1 handle (I ran them from a cloud host).
- **Do NOT run the CVE-2024-5798 auth-bypass against the live host** — attacking a production secrets manager's
  auth is unauthorized and will hurt you. To prove the CVE, do it in a **local lab** on Vault 1.16.2. The report
  below stands on the read-only exposure evidence alone.
- Realistic severity: **Low–Medium**; may be accepted as hardening/info-disclosure or closed by-design/known.
- Values below are the real, unabridged responses captured 2026-09-25 (server timestamps/raft indices will differ
  when you re-run — everything else is stable).

---

## ⤵ PASTE FROM HERE INTO HACKERONE

**Title:** Internet-exposed HashiCorp Vault (production secrets manager) on `vault.algolia.net` — unauthenticated information disclosure + outdated version with known auth-bypass CVE (CVE-2024-5798)

**Asset:** `vault.algolia.net` (in scope: `*.algolia.net`; resolves to `34.250.96.126`, `52.210.217.151`, `99.80.166.212`)
**Weakness:** CWE-668 Exposure of Resource to Wrong Sphere / CWE-200 Information Disclosure / CWE-1104 Use of Unmaintained Component
**Severity (self-assessed):** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)

### Summary
`vault.algolia.net` exposes a production HashiCorp Vault cluster to the public internet. Its unauthenticated system
endpoints respond `200` from any host and disclose the exact version (**Vault 1.16.2**, OSS), an internal hostname,
HA/raft state, and the enabled authentication backend (**Okta OIDC**). Version 1.16.2 is missing the fix for
**CVE-2024-5798** (HCSEC-2024-11), an authentication-bypass in Vault's JWT/OIDC auth method, so the vulnerable
component is enabled on an internet-reachable, unpatched instance. A secrets-management service should not be
reachable from the public internet and should be patched.

### Steps to reproduce (all unauthenticated, read-only — no headers/token required)

**1. Version, cluster identity, seal state**
```
$ curl -s https://vault.algolia.net/v1/sys/health
{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1790368041,"version":"1.16.2","enterprise":false,"cluster_name":"vault-cluster-0d3c6369","cluster_id":"9075ba06-d9e3-1e04-6ca5-e0369c7c595d","echo_duration_ms":28,"clock_skew_ms":-1}

$ curl -s https://vault.algolia.net/v1/sys/seal-status
{"type":"shamir","initialized":true,"sealed":false,"t":2,"n":18,"progress":0,"nonce":"","version":"1.16.2","build_date":"2024-04-22T16:25:54Z","migration":false,"cluster_name":"vault-cluster-0d3c6369","cluster_id":"9075ba06-d9e3-1e04-6ca5-e0369c7c595d","recovery_seal":false,"storage_type":"raft"}
```

**2. Internal hostname + HA/raft disclosure**
```
$ curl -s https://vault.algolia.net/v1/sys/leader
{"ha_enabled":true,"is_self":true,"active_time":"2026-08-04T08:01:30.581375143Z","leader_address":"http://hashicorp-vault-02.algolia.internal:8200","leader_cluster_address":"https://hashicorp-vault-02.algolia.internal:8201","performance_standby":false,"performance_standby_last_remote_wal":0,"raft_committed_index":7205148006,"raft_applied_index":7205148006}
```

**3. Unauthenticated auth-method enumeration**
```
$ curl -s https://vault.algolia.net/v1/sys/internal/ui/mounts
{"request_id":"4219bcba-6119-a403-ee8d-69880617a555","lease_id":"","renewable":false,"lease_duration":0,"data":{"auth":{"oidc/":{"description":"Okta OIDC","options":null,"type":"oidc"}},"secret":{}},"wrap_info":null,"warnings":null,"auth":null,"mount_type":""}
```

**4. OIDC provider enabled (issuer + public JWKS)**
```
$ curl -s https://vault.algolia.net/v1/identity/oidc/.well-known/openid-configuration
{"issuer":"https://vault.algolia.net/v1/identity/oidc","jwks_uri":"https://vault.algolia.net/v1/identity/oidc/.well-known/keys","response_types_supported":["id_token"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256","RS384","RS512","ES256","ES384","ES512","EdDSA"]}
```

All four return `200` with no authentication. For contrast, the privileged endpoints are correctly protected:
```
$ curl -s https://vault.algolia.net/v1/sys/internal/ui/resultant-acl
{"errors":["permission denied"]}
$ curl -s https://vault.algolia.net/v1/sys/ha-status
{"errors":["permission denied"]}
$ curl -s https://vault.algolia.net/v1/sys/metrics
Not Found
```
So the exposure is scoped to the unauth-by-design endpoints — but those still leak the data above to any internet client.

### Impact
1. A production Vault (secrets manager) is reachable from the public internet — the full API surface, including the
   `/v1/auth/oidc/*` login endpoints, is not restricted to an internal network, VPN, IP-allowlist, or mTLS.
2. The disclosed version **1.16.2** (build 2024-04-22) is missing **CVE-2024-5798 / HCSEC-2024-11** (fixed in
   1.15.9 / 1.16.3 / 1.17.0): Vault's JWT/OIDC auth method did not correctly validate the role-bound audience
   (`aud`) claim for array-type audiences, so a JWT with a mismatched audience could authenticate when it should be
   rejected. The vulnerable `oidc/` backend is confirmed enabled (step 3). Direct exploitability depends on the
   role's `bound_audiences`/`role_type` configuration and was **not** tested; the point is that the vulnerable,
   unpatched, enabled component is internet-reachable.
3. Additional information disclosure: internal hostname `hashicorp-vault-02.algolia.internal` (with internal ports
   8200/8201), unseal quorum (`t:2, n:18`), storage backend (`raft`), cluster name `vault-cluster-0d3c6369` and
   cluster id `9075ba06-d9e3-1e04-6ca5-e0369c7c595d`, build date, and the Okta OIDC auth topology.

### Remediation
- Restrict `vault.algolia.net` to internal networks / VPN / IP-allowlist, or require mTLS at the edge — do not
  serve the Vault API to the public internet (load-balancer health checks do not require public API exposure).
- Upgrade Vault to a current patched release; prioritized because the CVE-2024-5798-affected OIDC/JWT backend is
  enabled.
- Enforce strict `bound_audiences` / `bound_claims` on OIDC/JWT roles.

### Testing notes
All testing was unauthenticated, read-only, non-destructive, and limited to documented monitoring endpoints on an
in-scope asset. No authentication attempts, no exploitation of CVE-2024-5798, no writes.

## ⤴ PASTE TO HERE

---
_Generated by [Claude Code](https://claude.ai/code)_
