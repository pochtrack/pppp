# 10 — HackerOne Report Template (triage-proof)

A report gets paid when the triager can (a) reproduce it in under two minutes, (b) instantly see the impact, and
(c) rule out "duplicate / out-of-scope / won't-fix." Write for that reader. Below is a fill-in template plus the
pre-submit checklist and Algolia-specific framing.

---

## Template

```markdown
## Summary
<One or two sentences: what the bug is, which in-scope asset, and the impact in business terms.>
e.g. "An IDOR in the dashboard.algolia.com team-membership API (`PATCH /1/...`) lets any authenticated
member of one organization change roles in another organization, leading to cross-tenant privilege escalation."

## Asset / Scope
- In-scope target: <*.algolia.net | *.algolianet.com | dashboard.algolia.com | www.algolia.com>
- Exact host/endpoint: <full URL / API route>
- Weakness (CWE): <e.g. CWE-639 Authorization Bypass Through User-Controlled Key / CWE-284 / CWE-79 ...>

## Severity
- Self-assessed: <Critical/High/Medium/Low>
- CVSS 3.1 vector: <CVSS:3.1/AV:N/AC:L/PR:.../UI:.../S:.../C:.../I:.../A:...>  → score <x.x>
- Justify each metric in one line (esp. Scope-changed for cross-tenant, and C/I/A for data impact).

## Steps to Reproduce
1. Preconditions: <two of your own test accounts / two of your own app IDs, names/IDs given>
2. <exact request 1 — full method, URL, headers, body>
3. <exact request 2 ...>
4. Observe: <the precise response line / status / data that proves it>

Use real, copy-pasteable requests. Redact only your own secrets; keep app IDs/user IDs so triage can map them.

## Proof of Concept
- Attach: minimal curl commands / a short script / HAR / screenshots / short screen recording.
- Show the BEFORE (blocked/expected) and AFTER (bypassed) side by side where relevant.

## Impact
<Concrete, business-level. Who is affected, what an attacker gains, at what scale.>
e.g. "Any Algolia customer can read/modify indices belonging to any other customer's application, breaking the
core tenant-isolation guarantee of the platform."

## Root Cause (hypothesis)
<Where the check is missing/weak — e.g. server authorizes on the API key's app ID but not on the target
resource's app ID; secured-key `restrictIndices` not enforced on endpoint X.>

## Remediation
<Specific, actionable fix — e.g. enforce that the resource's application ID matches the credential's application
ID server-side on endpoint X; validate `restrictIndices`/`restrictSources` on the analytics endpoints.>

## Notes for triage
- Test accounts used: <appIDs / emails you control>. All actions were on assets I own.
- No third-party or other-customer data was accessed beyond the minimal PoC shown.
- Non-destructive; no DoS.
```

---

## Severity quick-reference (this program)

| Finding class | Typical band | Notes |
|---|---|---|
| Cross-tenant data read/write via API (any app can touch another app's indices/config) | **Critical** | Breaks the platform's core isolation guarantee. Scope:Changed. |
| Admin API key compromise / privilege escalation of a key's ACLs | **Critical/High** | Show what the extra ACLs let you do. |
| Secured API Key restriction bypass (`restrictIndices`/`filters`/`validUntil`/`restrictSources`) | **High/Critical** | The whole point of secured keys is enforcement; a bypass is high-impact. |
| Account takeover on dashboard (reset/email-change/OAuth chain) | **Critical/High** | Full chain PoC required. |
| IDOR/BOLA in dashboard team/app/billing | **High** | Show cross-user/cross-org, not just self. |
| SSRF (e.g. via Crawler/ingestion) reaching internal metadata | **High/Critical** | Prove reach (169.254.169.254 / internal hosts) — use OOB. |
| Stored XSS in dashboard (executes for another user) | **High** | Self-XSS alone is out of scope — show cross-user. |
| Reflected XSS / open redirect on www | **Low/Med** | Heavily duplicated; only with a real impact story or as a chain link. |
| Subdomain takeover of a dangling `*.algolia.net`/`*.algolianet.com` | **High** | Demonstrate control (serve a benign marker on a host you can claim). |

## Pre-submit checklist

- [ ] Target host matches an in-scope pattern **exactly**.
- [ ] Not an excluded class (see `01-scope-and-rules.md`); if borderline, lead with the impact/chain that makes it eligible.
- [ ] Reproduced **from a clean session** following my own steps.
- [ ] PoC is **minimal** — stripped to the fewest requests that prove it.
- [ ] Impact stated in **business terms**, not just "the parameter is reflected."
- [ ] **Dedup check** done (see `09-disclosed-bugs-and-dedup.md`): searched disclosed reports / writeups for the same
      root cause; if similar-but-distinct, I say why it's different (different endpoint, different bypass, higher impact).
- [ ] Only **my own** accounts/apps/data touched; no other-tenant data harvested.
- [ ] CVSS vector filled and each metric justified.
- [ ] Remediation is specific and correct.
- [ ] Secrets in the PoC are **mine** and rotated after (never paste a real customer's key).

## Framing tips that survive Algolia triage

- **Lead with tenant-isolation impact.** For an API/key bug, the money sentence is "customer A can affect customer
  B." Make the triager see the cross-tenant boundary being crossed in step 1.
- **Distinguish from the classic "leaked key" dupe.** Leaked-admin-key-in-JS reports are extremely common. If your
  finding is a *platform* enforcement flaw (a key doing more than its ACLs should allow, or an endpoint ignoring
  `restrictIndices`), say so explicitly and contrast with the mundane leaked-key case.
- **For SSRF/Crawler**, prove server-side reach with an out-of-band interaction (your own collaborator/interactsh
  domain) and, if safe, a read of cloud metadata — but stop at proof, don't pivot.
- **Attach a 20–40s screen recording** for multi-step dashboard chains; it collapses triage time dramatically.
