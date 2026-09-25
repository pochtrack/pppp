# 01 — Scope & Rules of Engagement

> **Program:** Algolia — Bug Bounty Program on HackerOne
> **Policy:** https://hackerone.com/algolia · **Scopes:** https://hackerone.com/algolia/policy_scopes
> **Company site:** https://algolia.com
> **Status:** Open · Public · Offers bounties · Bounty splitting allowed · No swag · Not a managed program
>
> **Authorized testing only.** Everything in this package assumes you test **only the in-scope assets below**,
> non-destructively, with **your own test accounts**, respecting rate limits, and never accessing another user's
> data beyond the minimum needed to prove impact. Out-of-scope assets and third-party services Algolia merely
> uses are **off-limits**.

## In-scope assets (authoritative)

Pulled from the hourly-updated HackerOne scope mirror `arkadiyt/bounty-targets-data`
(`data/hackerone_data.json`, handle `algolia`). **Re-verify against the live policy page before you start** — scope
changes and this snapshot can lag.

| Asset | Type | Bounty eligible | Max severity | What it is |
|---|---|---|---|---|
| `*.algolia.net` | WILDCARD | ✅ | **Critical** | Search / indexing REST API DSN infrastructure. Per-app hosts like `{APPID}-dsn.algolia.net`, `{APPID}-1.algolia.net`, plus service subdomains (insights, analytics, recommend, usage, monitoring, crawler, etc.). |
| `*.algolianet.com` | WILDCARD | ✅ | **Critical** | API / CDN hosts, e.g. `{APPID}-1.algolianet.com`, `{APPID}-2.algolianet.com`, `{APPID}-3.algolianet.com` (the fallback/retry hosts in the DSN strategy). |
| `dashboard.algolia.com` | URL | ✅ | **Critical** | Customer control-plane SPA: auth, teams/orgs, applications, index management, API-key management, billing, analytics. |
| `www.algolia.com` | URL | ✅ | **Critical** | Marketing / main website (also hosts docs, blog, pricing, sign-up, and may proxy app flows). |

**Out-of-scope assets:** none are enumerated as separate assets in the scope mirror. Treat anything **not** matching
the four patterns above as out of scope — in particular:
- Customer-owned content/indices you don't own (the wildcards are **multi-tenant**; only touch data in **your own**
  Algolia application/app-ID).
- Algolia sub-processors and third-party SaaS (status page vendor, support desk, CDN provider control panels, etc.).
- Corporate/employee infrastructure not on the listed hosts.

> ⚠️ **Multi-tenant wildcard caveat.** `*.algolia.net` / `*.algolianet.com` resolve to *customer* application hosts.
> "In scope" means **the Algolia platform behavior** is fair game (tenant isolation, key ACL enforcement, takeover of
> dangling customer hosts, API authz). It does **not** authorize you to attack a specific customer's data. Prove
> platform-level impact using **your own app IDs**; never pivot into another tenant's real data beyond a minimal,
> read-only, self-evident PoC — and if you can reach another tenant, that itself *is* the finding: document the
> capability, don't harvest the data.

## Reward model

- **Minimum reward:** $100. Reward scales with severity (CVSS + business impact); paid via HackerOne only.
- All four assets carry **max severity = Critical**, so a clean critical (RCE, cross-tenant data access, admin-key
  compromise, auth bypass, account takeover) is the top of the range.
- **Bounty splitting** is allowed (collaborate freely).
- Program responsiveness (from the mirror; indicative, not guaranteed): ~88% response efficiency, first response on
  the order of ~16h. Time-to-bounty can be long — plan for patience.

## Excluded / commonly-closed vulnerability classes

Do **not** burn time on these — they are typically ineligible or auto-closed on this program. **Confirm against the
live policy**, but the published exclusions are:

- **Login / Logout CSRF** (and CSRF on non-sensitive, unauthenticated actions).
- **DDoS / volumetric / stress testing** — never perform this; it's a rules violation, not just ineligible.
- **Social engineering** of Algolia customers or employees; phishing; physical attacks.
- **Self-XSS** with no path to cross-user impact.
- **Missing rate limiting** as a standalone report (rate-limit issues only matter as part of a real chain, e.g.
  brute-forcing that leads to ATO).
- **Reports that are only raw automated-scanner / tool output** — you must manually verify and demonstrate impact.
- **Spam / mail-bombing / unauthorized-message sending.**
- **Bugs in third-party software** Algolia merely uses (report those upstream).
- Generally low/no-impact classes many programs reject: missing security headers alone, clickjacking on non-sensitive
  pages, verbose version banners, best-practice-only TLS nits, `EXIF`/metadata, tab-nabbing, etc. — only report with a
  concrete impact story.

## Rules of engagement (operational)

- **Stay in scope.** Match every target host against the four patterns before sending a request.
- **Use tagged test accounts.** Create your own Algolia account(s)/app(s). If the program provides a test-account
  tagging convention on the policy page, follow it. Never test against a real customer's production data.
- **Non-destructive only.** No deletion of indices/records you don't own, no config changes to shared infra, no DoS,
  no data exfiltration beyond minimal PoC.
- **Rate-limit hygiene.** Tune all tooling to low concurrency and polite rates (see `04-recon-and-discovery.md`).
  Aggressive scanning gets researchers banned and taints the target for everyone.
- **No scanner-dumping.** Automation *surfaces candidates*; you *verify by hand* before reporting.
- **Coordinated disclosure.** Do not publicly disclose before Algolia resolves and authorizes disclosure.
- **Safe harbor.** Good-faith testing within scope and rules is authorized under the program's terms — read the live
  policy's safe-harbor language and stay inside it.

## Strategy for this scope (one-paragraph orientation)

This is a **tight, high-value scope**: two multi-tenant API wildcards plus the dashboard and marketing site. The
richest, least-duplicated bugs will come from **authorization and tenant-isolation** logic — Algolia's whole product
is "give many customers isolated, key-scoped access to shared search infrastructure," so the crown-jewel bug classes
are **API-key ACL/scope enforcement, Secured API Key restriction bypass, cross-application/cross-tenant access via the
REST API, and IDOR/BOLA + privilege escalation in the dashboard's team/org model**. Recon on the wildcards is mostly
useful for **subdomain-takeover of dangling customer DSNs** and for **fingerprinting the service subdomains**, not for
generic dir-busting. `www.algolia.com` is the classic spot for XSS/redirect/cache issues but is the most-tested and
most-duplicated surface. Spend automation time widely and cheaply; spend **manual** time on the key model and the
dashboard authz. See `03-hunt-plan.md` for the prioritized order of operations.

---
*Scope snapshot source: `arkadiyt/bounty-targets-data`. Always defer to the live HackerOne policy page for the
current authoritative scope and rules.*
