# 08 — Gaps & Extra High-ROI Tests (completeness critic)

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware.

---

A dedicated completeness-critic agent reviewed all six research facets and flagged the following. These are the attack surfaces and bug classes the facet researchers under-covered or mis-scoped — several are among the highest-expected-value, least-duplicated ideas for this program.

## Additions to the Algolia engagement package

### 1. Data-plane enforcement tests the facets missed (highest ROI, all Algolia-owned)
- **Facet-search / browse filter escape** — for every secured key and index-level filter, replay the same scope against `POST /1/indexes/{index}/facets/{facet}/query` and `POST /1/indexes/{index}/browse`. Filters and `attributesToRetrieve` are commonly enforced on `/query` but not on facet queries or browse, leaking hidden facet values and full records.
- **`getObjects` multi-index escape** — `POST /1/indexes/*/objects` with a `requests[]` array naming indices outside the key's `restrictIndices`. Test whether the per-request index is validated or only the top-level one (distinct from the multi-query search vector already listed).
- **Recommend API on in-scope DSN hosts** — `POST /1/indexes/*/recommendations` (related-products / FBT) is served on `{APPID}-dsn.algolia.net` (IN scope). Test ACL and cross-app isolation on this newer, under-tested endpoint; do NOT chase Crawler/Insights/Ingestion (out of scope hosts).
- **`/1/dictionaries/*` and `/1/clusters` (MCM)** — dictionary write ACL / cross-tenant leakage, and `X-Algolia-User-ID` / cluster-mapping enumeration and reassignment for cross-cluster reads.

### 2. Edge / CDN class (program-specific to the two wildcards)
- **Cross-tenant cache leak / poisoning** — confirm the shared edge keys its cache by `appID + API key`. If not, one tenant can receive or poison another's cached search response.
- **Asymmetric control enforcement** — a Referer/IP `restrictSources` control or auth tier may hold on `*.algolia.net` but not on the `*.algolianet.com` fallback CDN. Diff the two wildcards for every control.
- **Request smuggling / desync** across the two CDN providers (front-end/back-end parser differences), beyond host-header confusion.
- **`X-Algolia-API-Key` in the query string** on Algolia-owned apps -> key leaking into CDN cache entries, logs, or Referer.

### 3. Control-plane (dashboard.algolia.com) beyond auth/2FA
- **SSRF** — the single biggest blind spot: import-index-from-URL, logo/avatar fetch-by-URL, connector/webhook config. Test for cloud-metadata and internal-service reach. No facet tested SSRF at all.
- **File-import handling** — CSV/JSON/XML index import: XXE, stored XSS via filename/record content in the preview pane, decompression bombs.
- **Credentialed CORS on `api.dashboard.algolia.com`** — Origin reflection with `Access-Control-Allow-Credentials: true` turns any attacker page into a cross-origin reader of the victim's apps/keys (the search-API `CORS:*` is intentional and not reportable — prove it on the control plane).
- **DOM surface on Algolia-owned origins** — postMessage/iframe/WebSocket origin validation and prototype-pollution / DOM-clobbering gadgets in the dashboard/www bundles (distinct from the out-of-scope `algoliasearch-helper` CVE, which is a customer-embedded library).

### 4. Scope fence (add explicitly to avoid auto-closed reports)
- In scope: `*.algolia.net`, `*.algolianet.com`, `dashboard.algolia.com`, `www.algolia.com` — **nothing else**.
- Out of scope and being drifted into by the facets: `*.algolia.com` subdomain takeover (only `www` + `dashboard` are in-scope `.com`), and `analytics.algolia.com` / `insights.algolia.io` / `usage.algolia.com` / `crawler.algolia.com` / `personalization`/`query-suggestions.*` / `status.algolia.com` / `data.*.algolia.com`. Findings on these are triaged out-of-asset regardless of severity.

### 5. Framing rule for the whole package
The dedup warnings converge on one point: a leaked/over-privileged **customer** key is out-of-asset and saturated. Every credential finding must prove the key is shipped by an **Algolia-owned** asset (`www`/`dashboard` JS or docs) **or** demonstrate a **platform enforcement flaw** (isolation, secured-key restriction, ACL, cache) on Algolia's own infra. Recon techniques (`GET /1/keys/{key}` introspection, scanner sweeps, referer-bypass) are pivots, not standalone submissions.

---

## Full gap list

- FACET-SEARCH / BROWSE FILTER ESCAPE (uncovered): No facet tests whether secured-key filters, index-level filters, or attributesToRetrieve restrictions are enforced on POST /1/indexes/{index}/facets/{facet}/query and POST /1/indexes/{index}/browse. Filters frequently apply to /query but not to facet-value queries or browse, leaking hidden facet values / full records. Platform-level, unreported, high value.
- CDN-LAYER CROSS-TENANT CACHE LEAK / POISONING (uncovered): Nothing tests whether the shared edge (Fastly/other on *.algolianet.com and *.algolia.net) keys its cache by appID+API-key. If the cache key omits the credential, one tenant can receive another tenant's cached search response, or poison it. Also: a security control (Referer/IP restriction, auth tier) may be enforced on *.algolia.net but NOT on the *.algolianet.com fallback CDN. Program-specific to the two wildcards; high.
- getObjects MULTI-INDEX RETRIEVAL ESCAPE (uncovered as distinct vector): POST /1/indexes/*/objects lets one request pull objects from multiple indices by objectID. If the per-request index in the requests[] array isn't validated against the key's restrictIndices (checked only at top level), it's a concrete cross-index read distinct from the multi-query search vector already listed.
- RECOMMEND API ON IN-SCOPE DSN HOSTS (mis-scoped away): The Recommend API (POST /1/indexes/*/recommendations, related-products/frequently-bought-together) is served on {APPID}-dsn.algolia.net — IN scope — yet disclosed-bugs lumps 'Recommend' with out-of-scope products. ACL/tenant-isolation on this newer, under-tested endpoint is a genuine in-scope surface.
- DATA-PLANE authZ ON /1/dictionaries/* AND /1/clusters (MCM) (uncovered): Dictionary (stopwords/plurals/compounds) write ACL and cross-tenant leakage, plus /1/clusters userID mapping enumeration/reassignment for cross-cluster data access, are only glancingly mentioned (MCM userID enum). The write/enumeration authZ on these specific endpoints isn't a concrete test anywhere.
- SSRF IS TESTED NOWHERE: Dashboard URL-fetch features (import-index-from-URL, logo/avatar fetch-by-URL, connector/webhook configuration) can reach cloud metadata/internal services. No facet contains a single server-side-request-forgery idea — a notable blind spot on an authenticated control plane.
- DASHBOARD FILE-IMPORT HANDLING (uncovered): CSV/JSON/(XML?) index import on dashboard.algolia.com — untested for XXE, stored XSS via filename/record content rendered in the preview pane, and decompression/zip bombs.
- CLIENT-SIDE DOM SURFACE ON ALGOLIA-OWNED ORIGINS (uncovered): postMessage/iframe/WebSocket origin validation in the dashboard SPA and embedded widgets, and prototype-pollution / DOM-clobbering gadget chains in the dashboard/www bundles leading to DOM-XSS in the Algolia-owned origin. Distinct from the out-of-scope algoliasearch-helper CVE (a customer-embedded lib).
- CREDENTIALED CORS ON THE CONTROL PLANE (under-specified): recon lists CORS at med, but the concrete, high-value case is api.dashboard.algolia.com reflecting Origin with Access-Control-Allow-Credentials:true — that turns any attacker page into a cross-origin reader of the victim's apps/keys. Search-API CORS:* is intentional and worthless to report; the control-plane case is the one to prove.
- HTTP REQUEST SMUGGLING / DESYNC ACROSS THE MULTI-CDN EDGE (uncovered): Only host-header/SNI confusion is listed. Front-end/back-end parser differences across the two CDN providers fronting the wildcards are a separate, higher-impact desync class worth probing.
- X-Algolia-API-Key AS QUERY PARAM -> CACHE/LOG/REFERER LEAK (uncovered): Algolia accepts credentials in the query string; on Algolia-OWNED apps this can leak the key into CDN cache entries, access logs, or Referer headers — a key-disclosure vector that is Algolia's own bug, unlike the saturated customer-JS leaks.
- SCOPE-HYGIENE GAP: Multiple facets drift onto OUT-OF-SCOPE assets — *.algolia.com subdomain takeover (only www + dashboard .com are in scope), plus analytics/insights/usage/crawler/personalization/query-suggestions/status/data.* hosts. Any finding there is auto-closed; the package should explicitly fence testing to the four in-scope assets.
