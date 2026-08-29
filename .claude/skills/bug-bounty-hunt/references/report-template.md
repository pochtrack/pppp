# HackerOne report template (house style)

Optimized for fast triage and full bounty. Lead with impact, make repro
copy-pasteable, one vulnerability per report (unless a genuine chain).

> Personalize: replace this with the structure/tone from the user's own
> resolved reports once provided.

---

## Title
`[Severity] <Vuln class> in <feature/endpoint> allows <impact>`
Concrete and specific. Example:
`[High] IDOR in /api/v2/invoices/{id} allows reading other tenants' invoices`

## Summary
2–3 sentences: what the bug is, where it lives, and the concrete impact to the
business/users. A triager should grasp severity from this paragraph alone.

## Severity
- CVSS 3.1 vector + score, and the qualitative rating (Critical/High/…).
- One line justifying it against *this program's* data/users.

## Affected asset / endpoint
- URL(s), HTTP method, parameter(s), and the auth context required
  (unauthenticated / user A / admin).

## Steps to reproduce
Numbered, minimal, from a fresh session. Include exact requests:

```
1. Log in as User A (attacker).
2. Send:

   POST /api/v2/... HTTP/2
   Host: target
   Authorization: Bearer <A's token>
   Content-Type: application/json

   {"id": <B's resource id>}

3. Observe the response returns User B's data (see PoC).
```

Make identifiers/tokens obviously placeholders; never paste live secrets.

## Proof of concept
- Attach request/response captures, screenshots, or a short script/video.
- Prove **impact**: show the actual unauthorized data/action (redact real PII).
- Keep the PoC to the minimum needed to demonstrate the bug.

## Impact
Plain-language business impact: what an attacker gains, at what scale, and why
it matters (data exposure, account takeover, financial loss, etc.).

## Remediation
Specific, actionable fix (e.g. "enforce object-level authorization: verify the
authenticated user owns `{id}` before returning the resource"). Optional
references (OWASP/CWE).

## Notes
- Rate-limit friendly? Any prerequisites? Duplicate check done?
- Chain potential with other findings (link, but report separately).

---

## Pre-submit checklist
- [ ] In authorized scope; vuln class is eligible for bounty.
- [ ] Reproduced from scratch on a clean session/account.
- [ ] Impact demonstrated, not just anomalous behavior.
- [ ] CVSS set and justified.
- [ ] No live credentials/PII in body or attachments.
- [ ] One vulnerability per report.
- [ ] Remediation included.
