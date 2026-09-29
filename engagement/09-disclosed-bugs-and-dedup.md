# 09 — Disclosed-Bug Intelligence & Dedup Strategy

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware.

---

## Facet: Disclosed-Bug & Payout Intelligence — Algolia (HackerOne `algolia`)

**Method note & honesty caveat.** `hackerone.com` and every report/writeup mirror (gitbook, medium, secjuice, benzimmermann, h1.security.nathan.sx, ycombinator, securityweek) are blocked by this environment's egress proxy, and the GitHub MCP is scoped to a single repo — so I could not open raw reports. Everything below is reconstructed from search-engine summaries that read those pages. **Report existence, bug class, and affected asset are reliable; exact bounty amounts are mostly unknown** (only two hard data points survived: WCD `#1530066` = **$400**, third‑party info‑disclosure `#739251` = **$0**). Treat dollar figures as "unknown unless stated." The often-repeated "4,419 reports / $2,030,173 paid" figure is almost certainly a mis‑attributed HackerOne platform-wide stat, not Algolia's — **do not trust it**; Algolia's real disclosed corpus is on the order of a few dozen reports.

### Program economics (verified public facts)
| Fact | Value | Source |
|---|---|---|
| Platform | HackerOne, public, bounty-eligible | FireBounty / H1 |
| Minimum reward | **$100**, paid via HackerOne only | FireBounty |
| Max severity | Critical | task scope |
| Scopes | 3 (2 wildcard API, dashboard, marketing) | FireBounty |
| Observed bounty (WCD, PII) | **$400** (`#1530066`, disclosed Apr 2023) | search summary |
| Observed non‑payout | **$0** for 3rd‑party misconfig (`#739251`, 155 upvotes) | search summary |
| First H1 activity | ~2015–2016 (report IDs ~98k) | report ID range |

Takeaway: this is a **modest-payout program** with a long history. The $400 for a working web‑cache‑deception → PII chain, and $0 for a high‑upvote third‑party finding, signal that Algolia (a) pays real but not lavish bounties and (b) **rejects/does‑not‑pay anything that is a customer‑side or third‑party misconfiguration** — which is decisive for dedup strategy (see below).

### Disclosed report inventory (reconstructed)
Legend: **✅ in current scope** / **⚠️ legacy asset, likely OUT of current scope**. Current scope = `*.algolia.net`, `*.algolianet.com`, `dashboard.algolia.com`, `www.algolia.com`.

| ID | Title / class | Affected asset | Scope | Root cause (as reported) | Reward |
|---|---|---|---|---|---|
| `134321` | **RCE** on facebooksearch.algolia.com | facebooksearch.algolia.com | ⚠️ legacy | Rails `secret_key_base` committed to public GitHub + `CookieStore` → forge/serialize session cookie → RCE | unknown (high) |
| `1530066` | **Web Cache Deception → PII leak** | www.algolia.com | ✅ | Authenticated response cached under attacker path (random `*.css`); victim opens link → cache stores PII | **$400** |
| `504261` | **Web Cache Deception (XSS)** | algolia web | ✅/? | Cache-key confusion | unknown |
| `1157893` | **PHP‑FPM status page disclosure** | Algolia infra | ✅/? | Debug/status endpoint publicly reachable | unknown |
| `739251` | Info disclosure via **3rd‑party product** | external | out | Misconfigured 3rd‑party product exposed Algolia user info | **$0** |
| `118925` | **API key scoped to one index works on other indices** | Search REST API (`*.algolia.net`) | ✅ | Server didn't enforce `restrictIndices`/index scoping → cross‑index write | unknown |
| `99969` | **User w/ limited access to index** (privesc) | dashboard / keys | ✅ | Downgrading a user's privilege didn't propagate to the resulting ACL/API keys | unknown |
| `156520` | **Unauthorized team members leak data via `/1/admin/*`** | REST `/1/admin/*` | ✅ | RBAC bypass — restricted teammates could call admin endpoints | unknown |
| `145629` | **2FA bypass** | dashboard | ✅ | Auth logic | unknown |
| `128777` | No rate‑limit in 2FA → **bruteforce bypass** | dashboard | ✅ | Missing throttling on TOTP verify | unknown |
| `1276373` | Info disclosure → 2FA (chain) | dashboard | ✅ | Discusses old‑password / 2FA re‑auth gating on sensitive actions | unknown |
| `98012` | **Stored XSS** | dashboard | ✅ | resolved Jan 2016, rewarded | rewarded |
| `102755` | **Stored XSS in name field** (shows on most pages) | dashboard | ✅ | Unsanitized account "name" reflected across app | unknown |
| `156387` | **Stored XSS from Display Settings** | dashboard | ✅ | Settings value rendered unsanitized | unknown |
| `155576` | XSS on github.algolia.com | github.algolia.com | ⚠️ legacy | — | unknown |
| `200826` | **DOM XSS** on github.algolia.com | github.algolia.com | ⚠️ legacy | `user` param in `github-btn.html` | unknown |
| `203241` | **Reflected XSS** (search query) | algolia web | ✅/? | Search term reflected | unknown |
| `673273` | **Subdomain takeover** at recommendation.algolia.com | recommendation.algolia.com | ⚠️ legacy | Dangling CNAME → `recommendation.us` was registrable (Aug 2019) | unknown |
| `238890` | Sauce Labs `Access_key`/`User_name` leak | CI/infra | ⚠️ | Secret in CI config | unknown |

### CVEs in Algolia libraries
- **CVE‑2021‑23433** — Prototype pollution in `algoliasearch-helper` < **3.6.2** (`SearchParameters._parseNumbers` merge, no proto guard). CVSS ~5.9. Client‑side JS library; only exploitable if the app lets users define arbitrary search params. **Low relevance to the hosted assets** and likely falls under the program's "bugs in software Algolia's customers embed" — not a bounty on the DSN/dashboard. (Advisory GHSA‑vpf5‑82c8‑9v36.)
- No public CVEs surfaced for `instantsearch`, `docsearch`, the crawler, or the core `algoliasearch` clients as of this research.

### Mass API‑key leak incidents (public intel, mostly NOT this program's scope)
These dominate the "Algolia security" search space but are **customer‑side misconfigurations** — Algolia's program excludes "bugs in 3rd‑party software Algolia merely uses," and by symmetry does not pay for customers embedding their own admin keys:
- **CloudSEK, Nov 2022** — 1,550 apps leaking Algolia keys; **32 apps hardcoded ADMIN keys**; combined 2.5–3M+ downloads. Dangerous ACLs: `listIndexes` (info disclosure), `editSettings` (stored XSS via `highlightPreTag`), `addObject`/`deleteObject`/`deleteIndex` (defacement/destruction).
- **Ben Zimmermann, 2024/25** — **39 exposed admin keys** across DocSearch sites (Home Assistant, KEDA, vcluster, etc.). Method: used Algolia's public (now archived) **`docsearch-configs`** repo (~3,500 site configs) as a target list, scraped ~15,000 docs sites for frontend credentials. Root cause: DocSearch issues search‑only keys, but self‑hosted crawlers put the **write/admin key in the frontend config**.
- **`secjuice`** writeup — admin key (copied from Algolia's own doc snippets) instead of search key exposed internal docs, security policies, Slack messages across 20,000+ hosts.
- Tooling the community uses: **Algopwn** (audits a key's ACLs), plus the one‑liner key‑ACL recon below.

### The Algolia API‑key ACL model (attacker cheat‑sheet)
Three inputs are almost always client‑side: **App ID**, **API key**, **index name**. Key types: **Admin API key** (all ACLs — must never be in frontend), **Search‑only key**, **Secured/scoped keys** (HMAC‑signed restrictions), plus **Usage**, **Monitoring**, and **Analytics** keys. Dangerous ACLs if a key over‑permits: `listIndexes`, `addObject`, `deleteObject`, `deleteIndex`, `editSettings`, `settings`, `logs`, `analytics`, `seeUnretrievableAttributes`.

```bash
# 1) Enumerate what a discovered key can do (READ-ONLY recon):
curl -s "https://${APPID}-dsn.algolia.net/1/keys/${APIKEY}" \
  -H "X-Algolia-Application-Id: ${APPID}" \
  -H "X-Algolia-API-Key: ${APIKEY}"           # returns {"acl":[...],"indexes":[...]} for privileged keys

# 2) List indices (needs listIndexes) — info disclosure signal:
curl -s "https://${APPID}-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${APIKEY}"

# 3) editSettings → stored-XSS primitive (DESTRUCTIVE — OWN TEST APP ONLY):
#    highlightPreTag is echoed into every highlighted search result.
curl -s -X PUT "https://${APPID}.algolia.net/1/indexes/${INDEX}/settings" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${APIKEY}" \
  -d '{"highlightPreTag":"<img src=x onerror=alert(document.domain)>"}'
```
**Program‑scope caveat:** finding an over‑permissioned key on some *customer's* site is out of scope for the Algolia program. The bounty‑eligible version is a **server‑side flaw on Algolia's own `*.algolia.net` infra** that lets a *properly‑restricted* key exceed its ACL/index/app scope (the `#118925` class).

### Synthesis — over‑reported vs under‑explored
**OVER‑REPORTED / high dup risk (deprioritize or find a fresh twist):**
- Customer‑side leaked/over‑permissioned Algolia API keys (the entire CloudSEK/DocSearch/`secjuice` genre) — out of scope here and infinitely duplicated.
- XSS on the dashboard/marketing site — at least 6 historical (`98012`, `102755`, `156387`, `155576`, `200826`, `203241`); easy dup.
- Web Cache Deception on `www.algolia.com` — already reported twice (`1530066`, `504261`).
- 2FA rate‑limiting alone (`128777`) — now explicitly an **excluded** class ("missing rate limits alone").
- Subdomain takeover on `*.algolia.net`/`*.algolianet.com` — one already (`673273`); UpGuard reports current DNS looks clean, but wildcard scope still tempts mass recon → likely dup/empty.

**UNDER‑EXPLORED / best non‑dup impact (Algolia's OWN responsibility, bounty‑eligible):**
1. **Server‑side authorization on the Search/Indexing REST API (`*.algolia.net`).** The `#118925` pattern (a key exceeding its index restriction) and `#156520` (`/1/admin/*` RBAC bypass) are the highest‑signal precedents — server‑side scoping/tenant bugs, not customer misconfig. Look for `restrictIndices`/`restrictSources` not enforced, cross‑application isolation gaps on shared DSN clusters, and multi‑query `/1/indexes/*/queries` scope leaks.
2. **Secured API key (HMAC) validation** — tampering the signed restriction blob vs the signature, expired `validUntil` honored, filter‑injection to widen results.
3. **`dashboard.algolia.com` app logic** — team/RBAC (echo of `99969`/`156520`), IDOR on application/index/key management (`/1/keys`), invite/transfer flows, and re‑auth gating on sensitive actions (the `1276373` theme).
4. **Newer product surfaces with ZERO disclosed reports** (the disclosed corpus caps ~2022, report IDs ~1.5M): **Crawler API/dashboard** (SSRF via crawl targets), **Recommend**, **Query Suggestions**, **Insights/Analytics API**, **Ingestion/Connectors**, **NeuralSearch/AI**, and any **MCP** surface. These predate the disclosure set entirely → lowest dup probability.
5. **`seeUnretrievableAttributes` / `unretrievableAttributes` leakage** — attributes that must never return, recovered via faceting/highlighting/rules on the query API.

Bottom line for the hunter: **skip the leaked‑key genre**, aim at **server‑side authorization/tenant‑isolation on `*.algolia.net`** and **untouched new product APIs**, and treat dashboard XSS/WCD/2FA‑rate‑limit as already‑mined.

---

## Consolidated dedup warnings (all facets)

Areas that are likely already reported / saturated for Algolia — deprioritize, or only pursue with a genuinely fresh twist or a higher-impact chain:

- **[attack-surface]** Leaked/over-privileged customer API keys on *.algolia.net is the single most-reported Algolia class (CloudSEK mass disclosure, the '39 DocSearch admin keys' writeup, countless gitbook/medium posts). Against THIS program a third party's leaked key is out of scope/customer-side; only Algolia-OWNED keys (e.g. embedded on www.algolia.com/doc or dashboard.algolia.com) or an isolation flaw are novel. Deprioritize generic 'I found a key' reports.
- **[attack-surface]** The GET /1/keys/{key} self-introspection recon trick is extremely well known and documented; it is a technique, not a vuln. Do not report the technique itself.
- **[attack-surface]** Referer-restriction bypass is documented by Algolia as weak-by-design, so it will likely be closed as informative unless chained to real Algolia-owned data exposure.
- **[attack-surface]** Basic reflected XSS / open redirect on www.algolia.com marketing pages is a mature, heavily-scanned surface; expect duplicates unless you find a genuinely fresh sink (e.g. docs-search results template).
- **[attack-surface]** Missing rate limits / volumetric behavior on the search hosts is explicitly excluded (DDoS + missing-rate-limit-alone), and raw scanner output is non-reportable.
- **[attack-surface]** Do not spend time on analytics.algolia.com, insights.algolia.io, personalization/query-suggestions.*.algolia.com, crawler.algolia.com, data.*.algolia.com, status.algolia.com or the Usage API — they are real Algolia products but NOT in the four in-scope assets, so findings there will be closed as out-of-scope.
- **[api-key-model]** LEAKED CUSTOMER ADMIN KEY IN CLIENT JS: massively reported (Ben Zimmermann's 39-keys writeup, secjuice, rouvin/ibreakstuff, countless Medium posts, and automated key-scanner tools). For the ALGOLIA program specifically this is almost always closed as N/A because it is the customer's misconfiguration, not an Algolia platform flaw. Deprioritize unless the leaking app is Algolia's own (www.algolia.com / dashboard.algolia.com).
- **[api-key-model]** Basic index enumeration via listIndexes and 'search key returns records the site didn't intend' — heavily covered and again usually a customer-side config issue.
- **[api-key-model]** GET /1/keys/{key} ACL-introspection trick — well-known public technique (documented in most Algolia bug-bounty writeups); useful as a tool, not novel as a finding.
- **[api-key-model]** editSettings -> renderingContent stored XSS on a CUSTOMER site — documented pattern; only novel/valid here if the writable app is Algolia-owned.
- **[api-key-model]** To stand out, pivot to PLATFORM ENFORCEMENT bugs (ACL not enforced on a specific edge host tier, secured-key restriction/signature-scope bypass, cross-tenant isolation, unretrievableAttributes leak) and to dashboard.algolia.com key-management authZ (BOLA/IDOR) — these are Algolia-owned and far less reported than 'found a key in JS'.
- **[api-key-model]** Analytics/Usage/Insights key testing (analytics.algolia.com, usage.algolia.com, insights.algolia.io) is OUT OF SCOPE for this program (those are .algolia.com/.io, not the in-scope *.algolia.net / *.algolianet.com); don't burn a report there.
- **[disclosed-bugs]** Customer-side leaked/over-permissioned Algolia API keys (CloudSEK 2022, Ben Zimmermann DocSearch 39-keys, secjuice) — the single most saturated Algolia topic AND out of scope for this program (customer misconfig / not Algolia's own asset). Do not report finding an exposed key on some third-party site; only a server-side flaw on Algolia's OWN *.algolia.net infra counts.
- **[disclosed-bugs]** Dashboard/marketing XSS — at least 6 historical disclosed reports (#98012, #102755, #156387, #155576, #200826, #203241). Reflected/stored XSS on obvious fields is very likely a dup unless it's a genuinely new sink with cross-user impact (self-XSS is excluded).
- **[disclosed-bugs]** Web Cache Deception on algolia web properties — already reported twice (#1530066 paid $400, #504261). Needs a brand-new authenticated endpoint / novel cache-key twist to be non-duplicate.
- **[disclosed-bugs]** 2FA / login rate-limiting (#128777) — 'missing rate limits alone' is an explicitly EXCLUDED class now; a pure brute-force-rate finding will be closed N/A.
- **[disclosed-bugs]** Subdomain takeover across *.algolia.net / *.algolianet.com — one disclosed (#673273) and current DNS appears cleaned up (UpGuard); mass wildcard takeover recon is likely empty and, if it's raw scanner output, non-reportable.
- **[disclosed-bugs]** CVE-2021-23433 (algoliasearch-helper prototype pollution) — a client library bug, almost certainly treated as 'software Algolia's customers embed', not a bounty on the hosted DSN/dashboard.
- **[disclosed-bugs]** Raw automated-scanner output against the *.algolia.net wildcard — explicitly non-reportable to this program; any host-exposure finding must be manually validated and tied to an Algolia-owned in-scope asset.
- **[dashboard-auth]** 2FA/MFA issues are SATURATED for Algolia: disclosed #1276373 (info disclosure -> 2FA bypass -> POST exploitation), #128777 (no rate-limit on 2FA brute force, $100), #145629 (2FA bypass). Only report a genuinely novel MFA vector (e.g. MFA not enforced on the OAuth/Bearer API path).
- **[dashboard-auth]** Team-member deprovisioning / retained access is already reported: #156520 ('Unauthorized team members can leak information and see all API calls through /1/admin/* endpoints, even after they have been removed', $400). A new finding must be a distinct vector (e.g. surviving OAuth refresh token or admin API key), not the same class.
- **[dashboard-auth]** Search API-key ACL scoping is reported: #118925 ('API Key added for one Indices works for all other indices too', $1000). The 'exposed Admin API key in client-side code / docs snippets' class is extremely over-reported across dozens of Medium/GitBook writeups — do NOT submit a plain leaked-key finding; only a current ACL/index-restriction *bypass* is worth pursuing.
- **[dashboard-auth]** Web Cache Deception on algolia.com leaking PII is reported: #1530066 ($400). Cache-based PII leaks on the marketing/dashboard edge are likely triaged as dupes.
- **[dashboard-auth]** Info disclosure via misconfigured third-party products: #739251 (156 upvotes). Generic third-party/CORS info-leak reports are well-trodden.
- **[dashboard-auth]** Stored/reflected XSS on Algolia properties: #149154 ($100) and others — XSS on the dashboard is a common submission; needs a fresh, high-impact context (e.g. XSS executing with an authenticated dashboard session against api.dashboard.algolia.com).
- **[dashboard-auth]** Subdomain takeover: #673273 (recommendation.algolia.com) and directory traversal on msg.algolia.com (#333306) already disclosed — the low-hanging edge/subdomain issues are picked over.
- **[dashboard-auth]** General note: the dashboard control-plane AUTHORIZATION surface (BOLA on api.dashboard.algolia.com keyed by public appID, team/role tampering, invitation flows, plan self-serve) appears comparatively UNDER-reported publicly vs. auth/2FA/key-leak classes — this is where a non-duplicate high-impact bug is most likely, provided the API host is confirmed in the live HackerOne scope.
- **[api-infra]** Exposed Algolia admin/write keys in third-party frontends (DocSearch/docsearch-configs, npm/GitHub, JS bundles) is the single most-reported Algolia issue class (Ben Zimmermann's 39-key sweep, YAS Global, dozens of Medium/InfoSec write-ups). For the ALGOLIA program specifically these are almost always OUT of scope (the vulnerable app belongs to a customer = 3rd-party software Algolia merely powers). Only pursue keys that belong to an ALGOLIA-OWNED application (www.algolia.com/docs/dashboard). Everything else route to the customer.
- **[api-infra]** Permissive CORS (Access-Control-Allow-Origin: *) on the Search API is intentional (in-browser search) and the API is header/query authed, not cookie authed - so a CORS-only report has no CSRF/credential-theft impact and will be closed. Only report a credentialed CORS reflection on an admin/management endpoint.
- **[api-infra]** Subdomain takeover of {APPID}.algolia.net / algolianet.com hosts is a dead end (Algolia-controlled wildcard DNS resolves every APPID). recommendation.algolia.com (HackerOne #673273, 2019) is already reported/fixed. Only NON-APPID service hostnames with dangling third-party CNAMEs are live, and those are rare.
- **[api-infra]** Search-only public keys with search + listIndexes on prod indices are the intended design, not a finding - don't report a working public search key as 'exposed credential' unless its ACL shows write/admin/logs verbs or it reaches indices that should be private.
- **[api-infra]** Missing rate limits / volumetric abuse on the search API alone is explicitly an excluded bug class for this program.
- **[api-infra]** Referer-restriction bypass is documented by Algolia itself as a weak control, so a standalone referer-bypass report is low value unless chained into concrete cross-tenant or private-index access.
- **[api-infra]** Raw nuclei/httpx/scanner output against the wildcards is not reportable on its own - it only serves to select hosts to hand-test.
- **[recon-automation]** EXPOSED CUSTOMER ALGOLIA API KEYS (the classic 'Algolia API misconfiguration'): a leaked appID+adminKey in some website's JS enabling listIndexes/browse/addObject. This is the single most-reported Algolia pattern on the internet (KeyHacks, dozens of Medium writeups, 1,500+ apps in the Infosecurity report). It is almost always the CUSTOMER's bug, not Algolia's, so against THIS program it is a duplicate/out-of-asset/N-A. Only pursue if the key was shipped by an in-scope Algolia-OWNED asset (dashboard/www JS).
- **[recon-automation]** SUBDOMAIN TAKEOVER on *.algolia.com is already disclosed (prestashop.algolia.com #173417, recommendation.algolia.com #673273). Re-check for a FRESH dangling label rather than resubmitting known ones, and confirm the label is still in the current asset scope.
- **[recon-automation]** PHP-FPM / server-status style status-page disclosure was already reported (#1157893). Fresh instances only.
- **[recon-automation]** Generic info disclosure on algolia.com is disclosed (#739251) — differentiate any new finding.
- **[recon-automation]** Program-EXCLUDED classes that scanners will surface but you must NOT report as primary: login/logout CSRF, missing rate limits alone, self-XSS, DDoS/volumetric, and raw nuclei/scanner output pasted as a report.
- **[recon-automation]** Rate-limit-bypass / '429 can be evaded' reports are excluded and reproducing them looks like abuse — skip.
