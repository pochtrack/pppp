# 06 — Search/Indexing REST API & Wildcard Infra Testing

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware. The dashboard backend host `api.dashboard.algolia.com` and the management-plane APIs (analytics/insights/usage/crawler/personalization/query-suggestions/monitoring/ingestion) are NOT literally in the four-asset list — confirm their scope on the live policy page before sending tampered requests to them.

---

## Facet: `*.algolia.net` / `*.algolianet.com` — Search & Indexing REST API infrastructure

This is Algolia's core multi-tenant Search API surface. Every Algolia customer's data lives here, keyed by a 10-char uppercase **Application ID (APPID)**. For the *Algolia* program, the bugs that pay are **platform isolation / authorization flaws in this shared infrastructure** — not "customer X leaked their admin key" (that's the customer's problem and 3rd-party to Algolia; see dedup).

---

### 0. Scope reality check — READ THIS FIRST

| Thing | Where it lives | In the named scope? |
|---|---|---|
| Search/indexing API (`{APPID}-dsn.algolia.net`, `{APPID}.algolia.net`, `{APPID}-1..3.algolianet.com`) | `*.algolia.net`, `*.algolianet.com` | **Yes (wildcards)** |
| Analytics API (`analytics.algolia.com`, `analytics.us/de.algolia.com`) | `*.algolia.com` | **Not named** — only `dashboard.` & `www.` are listed |
| Insights API (`insights.algolia.io`, `insights.us/de.algolia.io`) | `*.algolia.io` | **Not named** |
| Personalization / Recommend / Query-Suggestions / Usage / Crawler (`*.algolia.com`, region-suffixed) | `*.algolia.com` | **Not named** |
| Monitoring API (`status.algolia.com`) | `*.algolia.com` | **Not named** |

> **Actionable caveat:** the insights/analytics/crawler/usage/monitoring hosts are on `*.algolia.com` / `*.algolia.io`, which are **outside the four named scope entries** (`*.algolia.net`, `*.algolianet.com`, `dashboard.algolia.com`, `www.algolia.com`). Treat them as reachable-but-unconfirmed: either ask the program to confirm inclusion, or test them **only via `dashboard.algolia.com`'s own XHR calls** (which are in scope and legitimately hit these backends). I document them below because a cross-tenant or authz flaw there is high-impact, but flag them explicitly in any report.

> **Whose app do I test?** Only **Algolia's own APPIDs** — the app IDs powering `www.algolia.com` site search, the docs search, and `dashboard.algolia.com`. Harvest those from Algolia's own frontends. A customer's leaked key found via `docsearch-configs` is out of scope for this program.

---

### 1. Host map

| Host | Role | R/W | Notes |
|---|---|---|---|
| `{APPID}-dsn.algolia.net` | Primary **read** (DSN, geo-routed via GeoIP DNS) | Read-optimized | API clients hit this first |
| `{APPID}.algolia.net` | Primary **write**/indexing | Read+Write | Bare APPID host |
| `{APPID}-1.algolianet.com` | Fallback #1 | R+W | **Different DNS provider** than `.net` (deliberate, for HA) |
| `{APPID}-2.algolianet.com` | Fallback #2 | R+W | |
| `{APPID}-3.algolianet.com` | Fallback #3 | R+W | Clients randomize among 1–3 |

All four hostnames are functionally equivalent API entrypoints for the same APPID/cluster; the split is an availability/retry strategy, not a security boundary. Because `.algolianet.com` uses a **different DNS provider and CDN edge** from `.algolia.net`, the two are worth diffing for inconsistent edge behavior (routing, header handling, error verbosity).

**DNS note that kills classic subdomain-takeover:** both wildcards are Algolia-controlled **wildcard DNS**. A nonexistent APPID like `ZZZZZZZZZZ-dsn.algolia.net` still resolves and returns `{"message":"Invalid Application-ID or API key"}`. You cannot register an app that "owns" an arbitrary hostname on Algolia's own domain, so dangling-CNAME takeover of `{APPID}` hosts is not viable. (See §3.9 for the narrow path that is.)

---

### 2. Base paths, headers & key ACLs

**Auth headers** (or their query-string equivalents `?x-algolia-application-id=&x-algolia-api-key=`):

```
X-Algolia-Application-Id: {APPID}
X-Algolia-API-Key: {KEY}
X-Algolia-Agent: <client string>   (informational)
```

**Core Search/Indexing paths (`/1/...`):**

| Path | Method | Required ACL | Purpose |
|---|---|---|---|
| `/1/indexes` | GET | `listIndexes` | List all indices (name, entries, size, updatedAt) |
| `/1/indexes/{index}` | GET | `browse` | Paginated index dump |
| `/1/indexes/{index}/query` | POST | `search` | Search |
| `/1/indexes/{index}/browse` | POST | `browse` | Full export of records |
| `/1/indexes/*/queries` | POST | `search` | Multi-index query (`requests[].indexName`) |
| `/1/indexes/*/objects` | POST | `search` | getObjects across indices by objectID |
| `/1/indexes/{index}/settings` | GET/PUT | `settings` / `editSettings` | Reveals `unretrievableAttributes`, `attributesForFaceting`, replicas |
| `/1/indexes/{index}/{objectID}` | GET/PUT/DELETE | `search`/`addObject`/`deleteObject` | Record CRUD |
| `/1/indexes/{index}/batch` , `/1/indexes/*/batch` | POST | `addObject`/`deleteObject` | Bulk writes |
| `/1/keys` | GET/POST | **admin** | List/create keys (admin-only) |
| `/1/keys/{key}` | GET | the key **itself** (or admin) | **Inspect any key's own ACL** — see §3.1 |
| `/1/logs` | GET | `logs` | Raw HTTP request logs — high-value, §3.7 |
| `/1/clusters` , `/1/clusters/mapping` , `/1/clusters/mapping/{userID}` | GET/POST | admin | Multi-cluster (MCM) userID→cluster mapping |
| `/1/security/sources` | GET/PUT | admin | IP allowlist |
| `/1/task/{taskID}` | GET | any | Async task status |

**Adjacent-service paths (off-wildcard, see scope caveat §0):**

| Host | Path | ACL |
|---|---|---|
| `analytics.algolia.com` | `/2/searches`, `/2/searches/noResults`, `/2/searches/noClicks`, `/2/filters`, `/2/hits`, `/2/countries`, `/2/abtests` | `analytics` |
| `insights.algolia.io` | `/1/events` (POST) | `search` (a search key is accepted) |
| `personalization.<region>.algolia.com` | `/1/profiles/{userToken}`, `/1/strategies/personalization` | `recommendation` |
| `usage.algolia.com` | `/1/usage/*` | `usage` |
| `status.algolia.com` (Monitoring) | `/1/status`, `/1/incidents`, `/1/inventory/servers`, `/1/latency`, `/1/reachability`, `/1/indexing/{cluster}` | Monitoring key (Premium/Elevate); many endpoints unauthenticated |
| `crawler.algolia.com` | `/api/1/crawlers`, `/api/1/crawlers/{id}/config`, `/api/1/crawlers/{id}/urls/crawl`, `/api/1/crawlers/{id}/reindex` | **HTTP Basic** `crawler_user_id:crawler_api_key` (distinct credential set) |

**Key ACLs** (the full grammar you must reason about for authz tests): `search`, `browse`, `addObject`, `deleteObject`, `deleteIndex`, `listIndexes`, `settings`, `editSettings`, `seeUnretrievableAttributes`, `analytics`, `recommendation`, `usage`, `logs`, `inference`, `admin`. A key also carries **restrictions**: `indexes[]` (glob-able, e.g. `dev_*`), `referers[]`, `validity`, `maxHitsPerQuery`, `maxQueriesPerIPPerHour`, `queryParameters`. Isolation/authz bugs are all about whether the server *actually enforces* these restrictions on every path.

---

### 3. Test methodology

#### 3.1 Fingerprint any key you find (the free recon move)
`GET /1/keys/{key}` authenticated **with that same key** returns its own `acl`, `indexes`, `referers`, `validity`, rate caps and query-param restrictions (with `description` set to `redacted` for non-admin). No admin needed. Do this first on every Algolia-owned key you harvest — it tells you exactly what to test next.

```bash
APPID=XXXXXXXXXX; KEY=yyyy
curl -sS "https://${APPID}-dsn.algolia.net/1/keys/${KEY}" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${KEY}" | jq .
```
If `acl` contains `addObject`/`deleteObject`/`editSettings`/`deleteIndex`/`logs`/`admin` and `indexes` is `["*"]` with no `referers`, you likely have a real finding on an Algolia-owned app. If it's `["search"]` restricted to prod indices with referers — that's the intended public key, keep moving.

#### 3.2 Cross-tenant isolation (the crown-jewel test — CRITICAL if it breaks)
Confirm APPID A's key cannot touch APPID B. Vary all three independently: host APPID, header APPID, key.

```bash
# Baseline: A's key on A -> 200
curl -s "https://${APPID_A}-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: ${APPID_A}" -H "X-Algolia-API-Key: ${KEY_A}"

# A's key on B's host + B header -> expect 403 "Invalid Application-ID or API key"
curl -s "https://${APPID_B}-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: ${APPID_B}" -H "X-Algolia-API-Key: ${KEY_A}"

# Split-brain: A's host, B's app header, A's key (does routing follow host or header?)
curl -s "https://${APPID_A}-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: ${APPID_B}" -H "X-Algolia-API-Key: ${KEY_A}"
```
**Confirm signal:** any `200` that returns *another app's* index list / records. Also test the multi-query and getObjects paths, where the target index/app is chosen in the **body**, not the URL — a mismatch between URL-APPID auth and body-index selection is the highest-yield place for a cross-tenant slip:

```bash
curl -s "https://${APPID_A}-dsn.algolia.net/1/indexes/*/queries" \
  -H "X-Algolia-Application-Id: ${APPID_A}" -H "X-Algolia-API-Key: ${KEY_A}" \
  -d '{"requests":[{"indexName":"<index-you-should-not-see>","params":"query=&hitsPerPage=1"}]}'
```

#### 3.3 Host-header / SNI routing confusion
Because the `.algolianet.com` edge is a different provider, test whether backend routing keys off the TLS SNI, the URL, or the `Host` header — and whether they can be desynced.

```bash
# Reach A's IP but claim to be B via Host header (SNI = A, Host = B)
curl -s "https://${APPID_A}-1.algolianet.com/1/indexes" \
  -H "Host: ${APPID_B}-1.algolianet.com" \
  -H "X-Algolia-Application-Id: ${APPID_A}" -H "X-Algolia-API-Key: ${KEY_A}"
# and the cross-domain variant: send to a .net host with an .algolianet.com Host, etc.
```
**Confirm signal:** response reflects B's data, or an error that leaks B's cluster identity. Also probe path/host normalization: `//1/indexes`, `/1//indexes`, `..;/`, trailing dot in Host (`{APPID}-dsn.algolia.net.`), and mixed-case APPID — inconsistent handling between the two CDN providers is where edge auth bugs hide.

#### 3.4 Secured API key restriction bypass (most Algolia-specific, high signal)
Secured (a.k.a. "generated") API keys = `base64( HMAC-SHA256(parentKey, queryParams) + queryParams )`. The embedded `queryParams` pin restrictions like `filters=user:123`, `restrictIndices=idx`, `restrictSources=IP`, `userToken=...`, `validUntil=...`. Algolia's promise: these are enforced server-side and `filters` are **ANDed** so a tenant can't be escaped. Test that promise:

- **Filter override / parameter precedence:** secured key embeds `filters=owner:me`; you *also* send `filters`, `facetFilters`, `optionalFilters`, or `tagFilters` at request time. Does the server AND them (safe) or let the request-time value override/loosen (broken multi-tenant isolation → IDOR across tenants)? Test each filter family separately — inconsistency between `filters` vs `facetFilters` vs legacy `tagFilters` is the classic slip.
- **`restrictIndices` escape via multi-query:** secured key restricted to `indexA`; send `/1/indexes/*/queries` with `indexName: indexB`.
- **`validUntil` in the past:** does an expired secured key still return `200`?
- **`restrictSources` (IP) bypass:** combine with §3.5 XFF spoofing.
- **`userToken` override for personalization:** send a different `userToken` at request time than the one signed into the key.

**Confirm signal:** results outside the embedded restriction (rows for another `userToken`/tenant, a non-permitted index, or after `validUntil`).

#### 3.5 Restriction bypass on a normal key (IP + Referer)
```bash
# IP-restricted key: try to spoof the source via XFF / X-Real-IP
curl -s "https://${APPID}-dsn.algolia.net/1/indexes/${IDX}/query" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${IP_KEY}" \
  -H "X-Forwarded-For: <allowlisted-ip>" -H "X-Real-IP: <allowlisted-ip>" \
  -d '{"params":"query="}'

# Referer-restricted key: Referer is documented as weak; test pattern-match flaws
#   allowed "algolia.com" -> try "https://algolia.com.attacker.tld/", "https://x.algolia.com.evil/",
#   empty Referer, and "https://algolia.com@evil/"
```
Referer bypass alone is low severity (Algolia itself calls it a light control), but chain it: a search key that *only* looked safe because of a referer lock is fully usable server-side if the lock is bypassable.

#### 3.6 Analytics / Insights / Usage authorization (scope-caveat §0)
- **Analytics cross-index:** a key restricted to `indexA` — request analytics for `indexB`. Broken object-level authz if it returns data.
```bash
curl -s "https://analytics.algolia.com/2/searches?index=${OTHER_INDEX}" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${KEY}"
```
- **Insights event spoofing / profile poisoning:** `/1/events` accepts a search key and an arbitrary `userToken`. Sending click/conversion events for a *victim's* `userToken` (or garbage volume) can poison personalization profiles and A/B test / analytics integrity. Non-destructive PoC: send one event with your own token, confirm `2x` accept, then argue the integrity impact.
```bash
curl -s -X POST "https://insights.algolia.io/1/events" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${SEARCH_KEY}" \
  -d '{"events":[{"eventType":"click","eventName":"poc","index":"'"${IDX}"'","userToken":"poc-token","objectIDs":["1"],"positions":[1],"queryID":"<from a real search>"}]}'
```

#### 3.7 `/1/logs` — info disclosure + privilege escalation
If any Algolia-owned key you find has the `logs` ACL, `GET /1/logs` returns recent raw HTTP requests **for the whole app**, including full query strings. Since keys can be passed as `?x-algolia-api-key=`, logs frequently contain **other keys (incl. admin) used in URLs**, client IPs, user agents, and query bodies (potential PII). This turns a low-priv `logs` key into an escalation primitive.

```bash
curl -s "https://${APPID}-dsn.algolia.net/1/logs?offset=0&length=100&type=all" \
  -H "X-Algolia-Application-Id: ${APPID}" -H "X-Algolia-API-Key: ${LOGS_KEY}" \
  | jq '.logs[] | {method,url,query_body,query_headers,ip,timestamp}'
```
**Confirm signal:** another API key visible in `url`/`query_headers`, or user PII in query bodies. Redact in your report and access the minimum.

Also mine **error verbosity** as passive disclosure: `Invalid Application-ID or API key` vs `Index {x} does not exist` vs `Method not allowed with this API key` vs `Index not allowed with this key` distinguishes valid-app / valid-index / missing-ACL / index-restriction — low severity alone but useful for building the app model.

#### 3.8 CORS — set expectations before you report
Search endpoints send permissive `Access-Control-Allow-Origin` **by design** (in-browser search is the product) and Algolia auth is **stateless header/query auth, never cookies** — so a permissive ACAO does **not** create CSRF or credential theft the way a cookie-authed API would. A CORS-only report here will be closed. Only worth escalating if you find an **admin/management endpoint** (`/1/keys`, `/1/logs`, settings writes) reflecting `Access-Control-Allow-Origin: <origin>` **with** `Access-Control-Allow-Credentials: true`, i.e. a genuine credentialed cross-origin path. Verify with a real preflight, don't assume.

#### 3.9 Subdomain takeover on the wildcards — where it's alive vs dead
- **Dead:** `{APPID}.algolia.net` / `-dsn` / `-1..3.algolianet.com` — wildcard DNS, no dangling possible, no takeover.
- **Alive (narrow):** **non-`{APPID}` service hostnames** under these zones that CNAME to a third-party (S3/CloudFront/Heroku/Fastly/GitHub Pages/marketing SaaS) which has been decommissioned. Algolia *has* had a dangling record historically (HackerOne #673273, `recommendation.algolia.com`), so the pattern is not hypothetical for the org — just check the `.net`/`.com` zones for it.
- **Method (safe):** passive CT/DNS only (crt.sh, subfinder/amass passive, DNS history) → for each *non-APPID* hostname, `dig CNAME` and check whether the target is unclaimed; confirm with the specific service's takeover fingerprint (e.g. NoSuchBucket, "There isn't a GitHub Pages site here"). **Do not** brute the wildcard (it resolves everything and proves nothing).

#### 3.10 Safe enumeration approach
```bash
# 1) Passive CT — wildcard certs mean few per-host leaves, but grab non-APPID names
curl -s "https://crt.sh/?q=%25.algolia.net&output=json"     | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=%25.algolianet.com&output=json"  | jq -r '.[].name_value' | sort -u

# 2) Passive subdomain sources (NO active brute of the wildcard)
subfinder -d algolia.net -all -silent
amass enum -passive -d algolia.net -d algolianet.com

# 3) The real APPID source: Algolia's OWN frontends (do this live; egress here is blocked)
#    grep site JS for the app id + public search key
#    curl -s https://www.algolia.com | grep -oiE '(applicationId|appId|x-algolia-application-id)[^,]{0,40}'
#    also inspect dashboard.algolia.com XHR in devtools for the app powering docs/site search

# 4) Politely probe candidate hosts (low concurrency, rate-limited)
httpx -l candidates.txt -rl 5 -threads 5 -status-code -title -silent
```
Keep concurrency low and honor rate limits. Raw scanner/`httpx`/`nuclei` output is **not reportable** to this program on its own — it only points you at the host to hand-test.

---

### 4. Highest-value targets, ranked
1. **Cross-tenant read/write** via multi-query/getObjects body-index selection (§3.2) — CRITICAL, core to Algolia's business.
2. **Secured-API-key restriction bypass** (§3.4) — breaks the exact mechanism customers rely on for per-user multi-tenancy; very Algolia-specific, likely fresh.
3. **`/1/logs` key/PII disclosure** as escalation from a low-priv Algolia-owned key (§3.7).
4. **IP/`restrictSources` bypass via XFF** (§3.5) on a source-restricted key.
5. **Insights profile/analytics poisoning** (§3.6) — subject to the §0 scope caveat.
6. **Dangling non-APPID hostname** in the `.net`/`.com` zones (§3.9) — low probability, high payout if live.

