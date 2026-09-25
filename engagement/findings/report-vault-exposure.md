# DRAFT HackerOne report — Internet-exposed HashiCorp Vault (outdated, OIDC auth enabled) on `vault.algolia.net`

> **Before submitting:** (1) dedup-search the program for "Vault" / "exposed infra" / "version disclosure". (2)
> Re-run the curls from your own environment with an identifying User-Agent to attribute the traffic to your handle.
> (3) This is a **hardening + info-disclosure** finding with an **applicable-but-unverified auth CVE**. Report it as
> Medium and be explicit that the CVE was **not** exploited — let Algolia's team assess exploitability against their
> role config. Do not claim Vault compromise.

## Summary
`vault.algolia.net` (in scope via `*.algolia.net`) exposes a production HashiCorp **Vault** cluster to the public
internet. Unauthenticated endpoints disclose: the exact version **v1.16.2** (OSS, outdated), an **internal
hostname** (`hashicorp-vault-02.algolia.internal`), HA/raft state, and — via the login-UI mounts endpoint — that
the **OIDC (Okta) auth method is enabled**. Because v1.16.2 predates the fix for **CVE-2024-5798** (a JWT/OIDC
audience & bound-claim validation flaw that can let an *invalid* login succeed, fixed in 1.16.3), the vulnerable
component is live and internet-reachable. A production secrets manager should not be internet-exposed and must be
patched.

## Asset / Scope
- In-scope target: `*.algolia.net`
- Host: `vault.algolia.net` → public AWS IPs `52.210.217.151`, `99.80.166.212`, `34.250.96.126`
- Weakness: CWE-668 (Exposure of Resource to Wrong Sphere) + CWE-200 (Information Exposure) + CWE-1104
  (Use of Unmaintained/Outdated Component); latent CWE-287 (Improper Authentication) via CVE-2024-5798.

## Severity
- Self-assessed: **Medium**
- CVSS 3.1 (this report, exposure + disclosure): `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` ≈ **5.3**.
- **Ceiling:** if CVE-2024-5798 is exploitable against the configured OIDC role(s), an attacker could obtain
  unauthorized authenticated access to Vault → **High/Critical**. This report does **not** demonstrate that; it
  establishes that the vulnerable, internet-reachable component and its enabled auth method are present.

## Steps to Reproduce (all unauthenticated, read-only)
```bash
# 1) Version + reachability
curl -s https://vault.algolia.net/v1/sys/health
# 200 -> {"initialized":true,"sealed":false,...,"version":"1.16.2","enterprise":false,
#         "cluster_name":"vault-cluster-0d3c6369","cluster_id":"9075ba06-..."}

curl -s https://vault.algolia.net/v1/sys/seal-status
# 200 -> {"type":"shamir","initialized":true,"sealed":false,"t":2,"n":18,"version":"1.16.2",
#         "build_date":"2024-04-22T16:25:54Z","storage_type":"raft","cluster_name":"vault-cluster-0d3c6369",...}

# 2) Internal hostname + HA/raft disclosure
curl -s https://vault.algolia.net/v1/sys/leader
# 200 -> {"ha_enabled":true,"is_self":true,"active_time":"2026-08-04T08:01:30Z",
#         "leader_address":"http://hashicorp-vault-02.algolia.internal:8200",
#         "leader_cluster_address":"https://hashicorp-vault-02.algolia.internal:8201",
#         "raft_committed_index":7202287407,"raft_applied_index":7202287407}

# 3) Unauthenticated auth-method enumeration (login-UI mounts endpoint)
curl -s https://vault.algolia.net/v1/sys/internal/ui/mounts
# 200 -> {"data":{"auth":{"oidc/":{"description":"Okta OIDC","type":"oidc"}},"secret":{}},...}
#        => the JWT/OIDC auth method (the component affected by CVE-2024-5798) is ENABLED.

# 4) OIDC provider is enabled (issuer + public JWKS)
curl -s https://vault.algolia.net/v1/identity/oidc/.well-known/openid-configuration
# 200 -> {"issuer":"https://vault.algolia.net/v1/identity/oidc","jwks_uri":".../keys",
#         "id_token_signing_alg_values_supported":["RS256",...]}
```
Properly protected (returned `permission denied`/404): `/v1/sys/ha-status`, `/v1/sys/internal/ui/resultant-acl`,
`/v1/sys/metrics` — so the exposure is scoped to the unauth-by-design endpoints, but those still leak the above.

## Impact
1. **Production secrets manager reachable from the public internet.** The full Vault API (including `/v1/auth/oidc/*`
   login endpoints) is reachable from any host — not restricted to an internal network/VPN/mTLS. This maximizes the
   attack surface of the most sensitive component in the stack.
2. **Applicable authentication CVE on the enabled auth backend.** **CVE-2024-5798 / HCSEC-2024-11** (fixed in
   1.15.9 / **1.16.3** / 1.17.0) is an auth-bypass in Vault's JWT/OIDC auth plugin: Vault did not correctly validate
   the role-bound **audience (`aud`) claim**, specifically for **array-type `aud` claims**, so a JWT whose audience
   did not match the role's `bound_audiences` could still validate and log in when it should have been rejected
   (code path `vault/builtin/credential/jwt/jwt.go`). This instance runs the unpatched **1.16.2** and has the
   `oidc/` backend (the same plugin that serves JWT-login roles) enabled and internet-reachable.
   **Precision / honesty:** the CVE concerns the **JWT audience validation** path; whether it is *directly*
   exploitable here depends on whether a role accepts direct JWT login (`role_type: jwt`) and its
   `bound_audiences`/`bound_claims` config — which was **not tested** (that requires attempting authentication,
   which is out of bounds for this report). The point stands that the vulnerable, unpatched component is enabled
   and exposed → it should be patched regardless.
3. **Information disclosure:** exact version + build date (CVE matching), internal hostname
   `hashicorp-vault-02.algolia.internal` + internal ports (8200/8201), HA/raft indices, unseal quorum (`t:2,n:18`),
   storage backend (raft), cluster id/name, and the enabled auth topology (Okta OIDC).

## What was NOT done (deliberately)
No authentication attempts, no OIDC/JWT login, **no attempt to exploit CVE-2024-5798**, no path brute-forcing, no
secret reads, no writes. Testing was limited to documented **unauthenticated, read-only** endpoints. This
establishes exposure + vulnerable-component presence, not a compromise.

## Remediation
- Remove `vault.algolia.net` from the public internet: restrict to internal network/VPN, IP-allowlist, or require
  mTLS at the edge. Health checks can be served to the LB without exposing the API to the world.
- Upgrade Vault to a current patched release (≥ latest 1.16.x, or a newer supported line) — prioritized because the
  OIDC/JWT auth method (CVE-2024-5798) is enabled.
- Review the OIDC role config (`bound_audiences`, `bound_claims`, `oidc_scopes`) to ensure claims are strictly
  validated regardless of version.

## Notes for triage
- Non-destructive, unauthenticated, in-scope (`*.algolia.net`) testing only.
- If the internet exposure is intentional/accepted-risk, the actionable asks remain: patch the CVE-affected version
  and tighten OIDC role validation.

---
_Generated by [Claude Code](https://claude.ai/code)_
