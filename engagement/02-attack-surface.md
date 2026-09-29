# 02 — Product & Attack-Surface Map

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware.

---

## Facet: Algolia Product & Attack-Surface Map (scoped to the 4 in-scope assets)

This section enumerates every Algolia product/feature, maps each to a concrete host, and marks whether that host is one of the four in-scope assets. The single most important finding for this program is a **scope boundary most hunters get wrong**: the two wildcards only cover the *data plane*; nearly every "management-plane" product API lives on apex domains that are **out of scope**.

### TL;DR scope reality

| In-scope asset | What actually lives here |
|---|---|
| `*.algolia.net` (wildcard) | Data plane only: Search, Recommend, Composition REST APIs + API-key mgmt, MCM, IP-allowlist. Hosts: `{APPID}.algolia.net`, `{APPID}-dsn.algolia.net` |
| `*.algolianet.com` (wildcard) | Retry/fallback mirrors of the same data plane: `{APPID}-1/-2/-3.algolianet.com` (different DNS provider, same clusters) |
| `dashboard.algolia.com` (URL) | The control-plane SPA: auth/SSO, team RBAC, per-app config, key creation, billing, secured-key generation, crawler UI. **This is where genuine Algolia-side authz/tenant bugs live.** |
| `www.algolia.com` (URL) | Marketing + `/doc` docs + `/blog` + code exchange + lead/demo forms. Algolia *dogfoods its own search* here (embedded search key → hits `algolia.net`, in scope). |

### Verified product → host → in-scope map

Grounded in Algolia's public OpenAPI specs (`algolia/api-clients-automation`, `specs/*/spec.yml`, `servers:` blocks) and docs.

| Product / feature | REST API | Base host(s) | In scope? |
|---|---|---|---|
| **Search & indexing** (core) | Search API | `{APPID}.algolia.net`, `{APPID}-dsn.algolia.net`, `{APPID}-{1,2,3}.algolianet.com` | **YES** (both wildcards) |
| **InstantSearch / Autocomplete / DocSearch** widgets | client libs → Search API `/1/indexes/*/queries` | same as above | **YES** (data plane); widget JS is client-side |
| **Recommend** (related, FBT, trending, looking-similar) | Recommend API `/1/indexes/*/recommendations` | `{APPID}.algolia.net` + algolianet.com mirrors | **YES** |
| **Composition** (federated/merchandising, newer) | Composition API `/1/compositions/*` | `{APPID}.algolia.net` + mirrors | **YES** |
| **MCM** (multi-cluster mgmt / userID→cluster) | Search API `/1/clusters/mapping*` | `{APPID}.algolia.net` | **YES** (admin ACL) |
| **API key management** | Search API `/1/keys*` | `{APPID}.algolia.net` | **YES** (admin ACL) |
| **Secured / restricted API keys** | client HMAC (`generateSecuredApiKey`), validated at query time | used against `algolia.net` | **YES** (impact realized on algolia.net) |
| **IP allowlist ("secured sources")** | Search API `/1/security/sources*` | `{APPID}.algolia.net` | **YES** (admin ACL) |
| **NeuralSearch / AI / Agent Studio** (`inference` ACL) | Search + AI/inference services | search on `algolia.net`; generative services separate | **PARTIAL** (search leg in scope) |
| **Analytics** (search analytics) | Analytics API | `analytics.algolia.com`, `analytics.{us,de}.algolia.com` | **NO** |
| **A/B Testing** | A/B Testing API | `analytics.algolia.com` / region | **NO** |
| **Insights / events** (clicks, conversions) | Insights API | `insights.algolia.io`, `insights.{region}.algolia.io` | **NO** (`.io`) |
| **Personalization** | Personalization API | `personalization.{region}.algolia.com` | **NO** |
| **Query Suggestions** | Query Suggestions API | `query-suggestions.{region}.algolia.com` | **NO** |
| **Crawler** (hosted web crawler) | Crawler API (**BasicAuth** userId:key) | `crawler.algolia.com/api` | **NO** |
| **Ingestion / connectors / Data Transformations** | Ingestion API (`/1/authentications`, `/1/destinations`, `/1/push`, `/1/transformations`) | `data.{region}.algolia.com` | **NO** |
| **Monitoring** | Monitoring API | `status.algolia.com` | **NO** |
| **Usage** | Usage API | usage host (algolia.com subdomain) | **NO** |

**Regions:** apps are pinned to `us` (default) or `eu`/`de`; region-specific management hosts exist (`analytics.de.algolia.com`, `insights.de.algolia.io`, `data.us.algolia.com`, `personalization.eu.algolia.com`, `query-suggestions.us.algolia.com`). All out of scope, but useful to recognize so you don't waste time reporting them.

> Consequence for hunting: if you find a leaked **admin key**, the *in-scope* impact you can demonstrate is limited to what runs on `algolia.net`/`algolianet.com` — reading/writing/deleting indices and records (`addObject`/`deleteIndex`), rewriting settings/synonyms/rules (`editSettings`), **minting new API keys**, **reading logs** (which leak other users' queries+IPs), **wiping the IP allowlist**, and **MCM userID enumeration**. Demonstrating analytics/personalization/crawler abuse would touch out-of-scope hosts — describe it but PoC only against in-scope hosts.

### The complete API-key ACL model (verified from `specs/search/paths/keys/common/schemas.yml`)

ACL enum (exact values): `addObject`, `analytics`, `browse`, `deleteObject`, `deleteIndex`, `editSettings`, `inference`, `listIndexes`, `logs`, `personalization`, `recommendation`, `search`, `seeUnretrievableAttributes`, `settings`. Plus the meta-permission **`admin`** (full control incl. `/1/keys`, MCM, security sources).

A key also carries restrictions: `indexes` (with `*` wildcards e.g. `dev_*`), `maxHitsPerQuery`, `maxQueriesPerIPPerHour`, `queryParameters`, `referers`, `validity`. Secured keys add `filters`, `restrictIndices`, `restrictSources`, `userToken`, `validUntil` (HMAC-SHA256 over the params, base64-wrapped).

**High-value ACL → endpoint map (all on `algolia.net`, all in scope):**

| Action | Endpoint | Required ACL | Why it matters |
|---|---|---|---|
| Search one index | `POST /1/indexes/{index}/query` | `search` | baseline |
| **Multi-query (what InstantSearch sends)** | `POST /1/indexes/*/queries` | `search` | the most common leaked-key sink; can query *any* index in the app in one call |
| Browse (dump all records) | `POST /1/indexes/{index}/browse` | `browse` | full data exfil past `maxHitsPerQuery` |
| List indices (enumerate tenant) | `GET /1/indexes` | `listIndexes` | reveals every index name in the app |
| See unretrievable attrs | (query) | `seeUnretrievableAttributes` | bypasses `unretrievableAttributes` (PII often hidden here) |
| Write/overwrite records | `POST /1/indexes/*/batch` | `addObject` | defacement / poisoning |
| Delete by filter / clear | `POST /1/indexes/{index}/deleteByQuery`, `/clear` | `deleteIndex` | destructive |
| Rewrite ranking/settings/rules/synonyms | `PUT /1/indexes/{index}/settings`, `/rules/*`, `/synonyms/*` | `editSettings` | search-result manipulation, stored-XSS into consumers |
| **List/create/patch/delete API keys** | `/1/keys*` | `admin` | privilege escalation & persistence |
| **Read raw logs (other users' queries + IPs)** | `GET /1/logs` | `logs` | cross-tenant info leak if isolation is weak |
| **Read/replace IP allowlist** | `/1/security/sources*` | `admin` | disable app-level IP restriction |
| **Enumerate/move userID→cluster** | `/1/clusters/mapping*` | `admin` | MCM tenant enumeration |

### Recon primitive #1 — self-introspect any key (in-scope, documented)

Per the spec (`getApiKey`, `description`): *"Gets the permissions and restrictions of an API key. When authenticating with other API keys, you can only retrieve information for that key, with the description replaced by `<redacted>`."* So **any** key can report its own ACL/indexes/validity by calling `GET /1/keys/{THE_KEY}` authenticated with itself. This is the canonical way to grade a leaked/embedded key and it lands on an in-scope host.

```bash
# Grade a key found in a page/JS bundle. Polite: single request.
APPID="XXXXXXXXXX"; KEY="the_key_you_found"
curl -s "https://${APPID}-dsn.algolia.net/1/keys/${KEY}" \
  -H "X-Algolia-Application-Id: ${APPID}" \
  -H "X-Algolia-API-Key: ${KEY}" | jq .
# -> {"acl":[...],"indexes":[...],"validity":..,"maxHitsPerQuery":..}
# If acl contains anything beyond "search"/"browse" on a PUBLIC page key => over-privilege.
```

### Recon primitive #2 — dogfood keys on the in-scope web apps

`www.algolia.com/doc` and `dashboard.algolia.com` are themselves Algolia customers: their pages embed an APPID + search key in JS/`<meta>`/`window.__` config for the on-page search. Because those keys hit `*.algolia.net` (in scope) and the apps are Algolia-owned, an **over-privileged Algolia-owned key** is a clean, non-duplicate, in-scope finding.

```bash
# Extract embedded Algolia creds from the in-scope marketing/docs + dashboard bundles.
for u in https://www.algolia.com/doc/ https://dashboard.algolia.com/; do
  curl -s "$u" | grep -oaiE '([A-Z0-9]{10})' | sort -u | head        # candidate APPIDs
  curl -s "$u" | grep -oaiE '(apiKey|search[_-]?key|X-Algolia-API-Key)["'\'' :=]+[a-f0-9]{20,64}'
done
# Then grade each with primitive #1 against {APPID}-dsn.algolia.net.
```

### Multi-tenant / app-isolation surface (the real Algolia-side prize on the wildcards)

The APPID appears **both** in the hostname (`{APPID}-dsn.algolia.net`) **and** in the `X-Algolia-Application-Id` header. Trust-boundary questions worth probing (non-destructively, with your own two test apps A and B):
- Does the platform bind the request to the *host* APPID, the *header* APPID, or the *key*? Mismatch = potential cross-tenant access. Test: host of app A, header of app B, key of app B (and permutations).
- On shared clusters, can app A's `listIndexes`/`browse`/`logs` ever surface app B's index names/records/queries?
- `/1/logs` returns query strings + client IPs — verify it is strictly scoped to the calling app.
- MCM `searchUserIds` / `getTopUserIds` — do they leak userIDs across apps on a shared cluster?

### Trust boundaries summary

- **Tenant isolation:** APPID (host+header) + API key. Shared physical clusters → isolation is logical, not physical. Highest-value class to test on `*.algolia.net`.
- **Key ACL boundary:** search-only vs admin; secured-key `filters`/`restrictIndices`/`validUntil`; restricted-key `referers` (spoofable — Algolia docs themselves say referer restriction is weak).
- **Dashboard RBAC (dashboard.algolia.com):** roles/permission categories = *Billing, Features (A/B, Query Suggestions, Analytics), Team (invite/see members), Crawler, Other (view/edit API keys)*. Owner is superuser. Test vertical (member→admin) and horizontal (across `applicationID`) escalation, and whether a low role can still hit key-management or crawler config via the dashboard's own backend API.
- **Account/org boundary:** SSO/SAML (single email domain), team invites, multi-app orgs. Invitation/SSO-domain-claim flows and "exempt admin from SSO" are classic auth-bypass hunting grounds — all on `dashboard.algolia.com`.
- **Billing:** plan/usage enforcement in the dashboard; free-tier limit bypass, per-record/-request quota tampering.

### "Where the money is" — prioritized for THIS scope

1. **`dashboard.algolia.com` RBAC / tenant IDOR (P1).** Real Algolia-owned code. Look for horizontal access across `applicationID`/`indexName`/team objects, low-role users reaching key-management or crawler endpoints, and the dashboard's XHR/GraphQL backend. Highest chance of a non-dup, high-severity, in-scope bug.
2. **App-isolation on `*.algolia.net` (P1).** Host-vs-header-vs-key APPID confusion; cross-tenant `logs`/`browse`/MCM leakage on shared clusters.
3. **Over-privileged Algolia-owned embedded keys (P2).** Grade the search keys on `www.algolia.com/doc` and `dashboard.algolia.com` via self-introspection; anything beyond `search` is reportable and in scope.
4. **Secured-key weaknesses (P2).** If Algolia's own apps generate secured keys, test filter-injection/bypass, missing `validUntil`, and whether `restrictIndices` is enforced server-side.
5. **`www.algolia.com` classic web bugs (P2/P3, likely dup-heavy).** Reflected/stored XSS in docs search rendering, open redirects, lead/demo form injection, exposed config in JS.

### Polite testing notes
- Keep concurrency ≤2 and add small delays; hammering `algolia.net` looks like the DDoS/rate-limit exclusions and is non-reportable.
- Use **only your own test apps** for any write/delete/isolation PoC. Never `addObject`/`deleteIndex` against a third party's app, even if a key leaks.
- Raw nuclei/scanner output against these hosts is explicitly non-reportable to this program — convert any signal into a hand-verified, impact-demonstrating PoC.
