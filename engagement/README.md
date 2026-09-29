# Algolia — HackerOne Bug-Bounty Engagement Package

A co-pilot engagement package for **authorized** bug-bounty hunting on Algolia's public HackerOne program
([`hackerone.com/algolia`](https://hackerone.com/algolia)). It maps the attack surface, prioritizes where to
spend manual effort, gives exact runnable recon/testing commands, and provides a triage-proof report template —
all fenced to the program's four in-scope assets and its rules of engagement.

## How this works (co-pilot model)

The environment this package was built in blocks direct network egress to the target, so **nothing here fires
packets at Algolia**. This is the standard bug-bounty co-pilot split:

- **This package**: scope, attack-surface model, prioritized plan, exact commands, per-bug-class testing
  procedures, dedup intel, report template.
- **You**: run the commands against the in-scope assets **from your own authorized environment**, using **your
  own test accounts / app IDs**, non-destructively and within rate limits.
- **Loop back**: paste tool output (subdomain lists, `httpx`/`nuclei` results, JS files, Burp requests/responses)
  into `engagement/artifacts/` or the chat, and the analysis continues — separating signal from noise, deciding
  what to chase, escalating, and drafting the write-up.

## Scope (authoritative snapshot — always re-verify against the live policy)

| Asset | Type | What it is |
|---|---|---|
| `*.algolia.net` | WILDCARD | Search/indexing REST-API DSN infra (`{APPID}-dsn.algolia.net`, `{APPID}.algolia.net`) |
| `*.algolianet.com` | WILDCARD | API fallback/retry + CDN hosts (`{APPID}-1..3.algolianet.com`) |
| `dashboard.algolia.com` | URL | Customer control-plane SPA |
| `www.algolia.com` | URL | Marketing / main site |

All four are bounty-eligible, **max severity Critical**. Excluded classes and full RoE are in `01`.

## The rule that decides everything

> A leaked/over-privileged **customer** key is out-of-asset and saturated → auto-closed. Every credential or
> data-access finding must prove a key shipped by an **Algolia-owned** asset, **or** a **platform enforcement
> flaw** (tenant isolation, secured-key restriction, ACL, edge cache) on Algolia's own infra, reproduced with
> **your own** app IDs. Recon techniques are pivots, not submissions.

## Where to focus (short version)

The tight, multi-tenant scope means the freshest, best-paying, least-duplicated bugs are in **authorization and
tenant isolation**:
1. **Data-plane platform enforcement** on the wildcards — cross-tenant isolation, secured-key restriction bypass,
   ACL/`unretrievableAttributes` enforcement, `/1/logs` disclosure, facet/browse filter escape, edge-cache leaks.
2. **Control-plane authorization** on the dashboard — BOLA/IDOR keyed by the public app ID, team/role/invite
   privilege escalation, OAuth/reset ATO chains, SSRF via URL-fetch features.

Deprioritize (mined/duplicated): `www` XSS/redirect/web-cache-deception, 2FA rate-limiting, subdomain takeover on
the wildcards, and anything on the out-of-scope management-plane hosts.

## Files

| File | Contents |
|---|---|
| `01-scope-and-rules.md` | Authoritative scope, excluded classes, rules of engagement, per-scope strategy |
| `02-attack-surface.md` | Product → host → in-scope map; the data-plane vs management-plane boundary; full ACL model |
| **`03-hunt-plan.md`** | **Start here.** Framing rule, scope corrections, phased order of operations, ranked top-10, cross-facet chains |
| `04-recon-and-discovery.md` | Copy-pasteable recon/JS/URL/param/nuclei pipeline tuned to the scope + Algolia wordlist + politeness hygiene |
| `05-api-key-testing.md` | API-key & secured-key model, ACL impact map, non-destructive validation curls, enforcement hypotheses |
| `06-api-infra-testing.md` | REST API endpoints, cross-tenant tests, host-header confusion, CORS reality, subdomain-takeover reality |
| `07-dashboard-testing.md` | Control-plane architecture, confirmed API routes, authz-first test plan, ATO chains |
| `08-gaps-and-extra.md` | Completeness-critic additions: facet/browse filter escape, CDN cache class, SSRF, file-import, credentialed CORS, DOM |
| `09-disclosed-bugs-and-dedup.md` | Reconstructed disclosed-report inventory, CVEs, program economics, over- vs under-reported synthesis, dedup warnings |
| `10-report-template.md` | Triage-proof HackerOne report template, severity quick-reference, pre-submit checklist |
| `notes/` | Your per-host/endpoint/hypothesis notes |
| `artifacts/` | Drop tool output here to analyze |

## Suggested first session

1. Read `01` (scope) and `03` (plan).
2. Phase A recon from `04` (passive) + spin up two of your own free Algolia apps.
3. Start hand-testing Phase B (data-plane enforcement, `05`/`06`/`08`) against your own apps.
4. In parallel, Phase C dashboard authz diffing (`07`) with owner vs low-priv member tenants.
5. Paste anything interesting back for analysis; when something's real, write it up with `10` after a dedup pass
   against `09`.

---

> **Sourcing & honesty.** Scope is from the hourly `arkadiyt/bounty-targets-data` mirror. Endpoint/ACL/secured-key
> details are grounded in Algolia's public OpenAPI specs and open-source clients. Disclosed-report details were
> reconstructed from search-engine summaries (report mirrors were egress-blocked during research) — treat report
> IDs/classes as reliable and dollar figures as "unknown unless stated." **Always defer to the live HackerOne
> policy page for current scope and rules.**
