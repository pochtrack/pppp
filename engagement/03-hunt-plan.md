# 03 — Prioritized Hunt Plan

> This is the **brain** of the package: where to spend manual time for the highest expected value on Algolia's
> scope, in what order, and why. It reconciles all six research facets (`02`, `04`–`09`) plus a completeness
> critic. Read `01-scope-and-rules.md` first for the scope fence.

## The one framing rule that decides whether you get paid

Algolia's whole product is *"give many customers isolated, key-scoped access to shared search infrastructure."*
So the dedup data converges on a single point:

> **A leaked or over-privileged _customer_ API key is out-of-asset and infinitely duplicated — it will be closed
> N/A/Informative.** Every credential or data-access finding must be one of:
> 1. a key shipped by an **Algolia-owned** asset (`www.algolia.com` / `dashboard.algolia.com` JS or docs), **or**
> 2. a **platform enforcement flaw** on Algolia's own infra (tenant isolation, secured-key restriction, ACL
>    enforcement, edge/CDN cache), reproduced with **your own** test app IDs.

Recon techniques — `GET /1/keys/{key}` introspection, scanner sweeps, Referer-restriction "bypass" alone — are
**pivots, not standalone submissions**. If your PoC touches another customer's real data, you've broken the rules
*and* found the customer's bug, not Algolia's.

## Scope corrections (apply these over the individual facet docs)

The facet docs occasionally drift; the critic reconciled them. Authoritative rulings:

- **Only four assets are in scope:** `*.algolia.net`, `*.algolianet.com`, `dashboard.algolia.com`,
  `www.algolia.com`. **Nothing else.**
- **OUT of scope (do not report; auto-closed):** `*.algolia.com` subdomain-takeover on any label other than
  `www`/`dashboard`; and the management-plane APIs on their own hosts — `analytics.algolia.com`,
  `insights.algolia.io`, `usage.algolia.com`, `crawler.algolia.com`, `personalization.*`,
  `query-suggestions.*`, `status.algolia.com`, `data.*.algolia.com`.
- **`api.dashboard.algolia.com`** (the dashboard's real backend) and the management APIs are best reached
  **only via the in-scope SPA's own XHR** unless the live policy confirms them as in scope — **verify before
  tampering.**
- **Recommend API** (`POST /1/indexes/*/recommendations`) and **MCM/clusters** (`/1/clusters/*`) **are in
  scope** — they're served on `{APPID}-dsn.algolia.net`. Newer and under-tested; good hunting.
- **Secured-API-key restriction bypass is HIGH/CRITICAL**, not medium (one facet undersold it).
- **Subdomain takeover on the two wildcards is LOW** — they're Algolia-controlled wildcard DNS, so `{APPID}`
  hosts can't dangle. Only a *non-`{APPID}`* service label with a dangling CNAME to a dead SaaS is viable
  (rare; one historical case). Passive-only; never brute the wildcard.
- **`GET /1/keys/{key}` introspection** and **Referer-restriction bypass alone** are recon pivots / low-severity,
  not standalone highs.

## Order of operations

Run automation (Phase A) in the background while you hand-test (Phases B→D). Most of the money is in B and C.

### Phase A — Recon & discovery (mostly passive, automated) → `04`
1. Passive CT/subdomain enum on both wildcards; **bucket** hosts into *Algolia-owned services* vs *multi-tenant
   customer DSN nodes* (heuristic in `04 §3`). Hand-test only the owned bucket.
2. JS analysis of `dashboard.algolia.com` + `www.algolia.com`: harvest **Algolia's own** app IDs, public search
   keys, and API endpoints (esp. `api.dashboard.algolia.com` routes). Grade every harvested key's ACL (pivot).
3. Historical URLs + param discovery. Polite nuclei (`takeovers`, `cors`, `exposures`, `misconfiguration`, `cves`)
   to **surface candidates only** — never a report on its own.
4. Spin up **two of your own free Algolia apps** (attacker/victim tenants) — the oracle for every platform test.

### Phase B — Data-plane platform enforcement (the crown jewels) → `05`, `06`, `08`
This is the freshest, highest-value, least-duplicated surface. Build oracles in your own apps, then look for
divergence between what you signed/scoped and what the edge enforces.
- **Cross-tenant isolation** on shared DSN hosts: mismatch hostname-APPID vs `X-Algolia-Application-Id` header vs
  the key's owning app; abuse body-selected index in `POST /1/indexes/*/queries` and `/1/indexes/*/objects`.
- **Secured-key restriction bypass**: unsigned request-time `restrictIndices`/`filters`/`facetFilters`/
  `restrictSources`/`validUntil` overriding the signed values; expired-key replay; `restrictIndices` escape via
  multi-query.
- **ACL enforcement**: a key performing an op its `acl` excludes; `seeUnretrievableAttributes` /
  `unretrievableAttributes` read via `browse`/`attributesToRetrieve=["*"]`/faceting oracle.
- **Facet-search & browse filter escape**: prove secured/index filters are enforced on `/query` but NOT on
  `/1/indexes/{index}/facets/{facet}/query` or `/browse` (`08` gap — uncovered, high value).
- **`/1/logs` disclosure**: if an Algolia-owned key has the `logs` ACL, harvest other requests' keys + query PII →
  escalate to admin.
- **Edge/CDN class** (`08`): is the shared cache keyed by appID+key? asymmetric control enforcement between
  `*.algolia.net` and the `*.algolianet.com` fallback; `X-Algolia-API-Key` in query string leaking to cache/logs.

### Phase C — Control-plane authorization on the dashboard → `07`, `08`
The dashboard addresses tenants by the **public Application ID** → textbook BOLA/IDOR. Diff an **owner** vs an
invited **low-priv member** (two test tenants) through Burp to see which fields the server actually authorizes.
- **BOLA** on `GET /1/application/{appID}`, key create/rotate (`/1/applications/{appID}/api-keys[/{uuid}/rotate]`),
  settings, plan, team — read/mutate another tenant.
- **Privilege escalation within a team**: tamper the permission/role/index fields on member-update and
  invite/accept flows; invitation token not bound to the invited email (join arbitrary org); stale access after
  deprovisioning (echo of report #156520).
- **Account-takeover chains**: OAuth `redirect_uri` validation (loose match, loopback port for the CLI client,
  PKCE downgrade); password-reset host-header injection / token reuse; email-change without re-auth; session
  fixation.
- **SSRF** (`08` — total blind spot): dashboard URL-fetch features (import-index-from-URL, logo/avatar fetch,
  connector/webhook config) reaching cloud metadata / internal services. Trigger on the in-scope origin; confirm
  the requesting host and use OOB.
- **File-import handling**: CSV/JSON/XML index import → XXE, stored XSS via filename/record in the preview pane.
- **Credentialed CORS** on `api.dashboard.algolia.com`: Origin reflection + `Access-Control-Allow-Credentials:
  true` = cross-origin reader of the victim's apps/keys (the search-API `CORS:*` is intentional and worthless).

### Phase D — www + misc, and chain assembly → `02`, `07`
`www.algolia.com` XSS/redirect/cache is the **most-duplicated** surface — only touch it as a **chain link** or
with a concrete impact story. Then assemble chains (below).

## Top 10 test ideas (ranked, non-duplicate, highest EV)

| # | Idea | Where | Why it pays |
|---|---|---|---|
| 1 | **Cross-tenant isolation break** on shared DSN via host-APPID vs header-APPID vs key confusion (read/write another app's data) | `06 §3.2` | Critical cross-tenant impact on Algolia's own edge; platform-level, under-reported |
| 2 | **Secured (HMAC) key restriction bypass** — unsigned `restrictIndices`/`filters`/`restrictSources`/`validUntil` override signed values; per-request index not re-checked in `*/queries`,`*/objects` | `05 §6`, `06 §3.4` | Turns a scoped public key into cross-index/unfiltered access; Algolia enforcement bug, not "found a key" |
| 3 | **BOLA/IDOR on the control plane** keyed by public `applicationID` — read/mutate another tenant's app, keys, settings, team | `07 §5.1–5.2` | appID is public; control-plane authz is the least-saturated zone; cross-tenant compromise |
| 4 | **`/1/logs` cross-request disclosure** on an Algolia-owned app → harvest other users' keys + query PII → admin | `06 §3.7` | Known endpoint × in-scope Algolia-owned asset; real key/PII exfil, escalates to admin |
| 5 | **`unretrievableAttributes`/`seeUnretrievableAttributes` enforcement gap** — read hidden fields via a key lacking the ACL, or via browse/`attributesToRetrieve=*`/faceting oracle | `05 §5(d)`, `06` | Pure server-side ACL flaw; high-value info disclosure; fresh angle |
| 6 | **Facet-search & browse filter escape** — filters enforced on `/query` but not `/facets/{f}/query` or `/browse` | `08 §1` | Uncovered by every facet; classic real Algolia gap; clean tenant/data-scope bypass |
| 7 | **CDN cross-tenant cache leak / poisoning** on the shared `*.algolianet.com`/`*.algolia.net` edge (cache key omitting appID/key); asymmetric control enforcement between the two providers | `08 §2` | Cross-tenant exposure at the edge *without holding the victim's key*; program-specific, uncovered |
| 8 | **OAuth `redirect_uri` bypass** on dashboard chained to an **open redirect on www** → code/token exfil → full ATO | chain, `07 §5.6` | Highest control-plane impact; both hosts in scope; canonical cross-facet chain |
| 9 | **Invitation/team flows** — invite token not bound to invited email (join arbitrary org); permission-field tampering on invite/accept | `07 §5.3–5.4` | Under-reported control-plane authz; high-impact cross-org access |
| 10 | **Stored XSS via index settings** (`renderingContent`/`userData`/`synonyms`/`rules`) rendered in the dashboard preview, firing for a **shared team member** → drive control-plane API to mint an admin key | chain, `07`+`05` | Cross-user (not excluded self-XSS), fresh sink vs the 6+ historical dashboard-XSS dups, escalates to key creation |

## Cross-facet chains worth building

1. **Open redirect on `www.algolia.com` → OAuth `redirect_uri` bypass on dashboard → code/token exfil → full
   account takeover.** `www` being in scope makes it the ideal redirect gadget host.
2. **Algolia-owned embedded search key → `GET /1/keys/{key}` introspect → if `logs`/`listIndexes` → read
   `/1/logs` on that Algolia-owned app → harvest others' keys + PII → escalate to admin.**
3. **Secured-key restriction bypass + facet/browse filter escape → drop the tenant filter AND pivot to a private
   index / hidden facet values → cross-tenant private-data disclosure.**
4. **Host-vs-header-vs-key APPID confusion + shared `*.algolianet.com` cache not keyed by appID → read/poison
   another tenant's cached response at the edge — without holding the victim's key.**
5. **Stored XSS via index settings rendered in the dashboard preview + same-origin/CSRF-able key creation → a
   shared team member opens the poisoned index → script mints an admin key / exfils session.**
6. **Credentialed CORS reflection on `api.dashboard.algolia.com` + attacker page (or the www open redirect) →
   cross-origin read of the victim's apps/keys using their dashboard token.**

## Timeboxing

- Spend the **first pass** on Phase B (data-plane enforcement, your own apps) — it's the freshest surface and
  provable without touching anyone else's data.
- Run Phase C in parallel with a second test tenant (Burp owner-vs-member diff).
- Cap `www` XSS/redirect/WCD spelunking hard — it's mined; only keep what becomes a chain link.
- Note every odd response (error-string differences, timing, header quirks) in `notes/` — half of a good bug is
  remembering the weird thing from an hour ago.
