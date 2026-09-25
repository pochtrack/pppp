# 05 — API-Key & Secured-Key Testing

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware.

---

## Facet: Algolia API Key & Credential Security Model

This is the highest-value facet for the Algolia program because the entire product is a credential-gated multi-tenant search API. Everything an attacker can do against `*.algolia.net` / `*.algolianet.com` flows from **what a key is allowed to do** and **how well Algolia's edge enforces the restrictions encoded into that key**. The reportable-to-Algolia angle is *platform enforcement failure*, not "I found a customer's leaked key" (see the scoping note at the end).

### 1. Credential types (VERIFIED PUBLIC FACTS)

| Credential | Public? | Where it lives | Notes |
|---|---|---|---|
| **Application ID** (`APPID`, e.g. `latency`, `BH4D9OD16A`) | Yes, always public | frontend, DSN hostname | Identifies the tenant; sent as `X-Algolia-Application-Id`. Also *is* the hostname prefix. |
| **Admin API key** | MUST be secret (server only) | server env | All ACLs incl. `editSettings`, `deleteIndex`, key management. Full compromise of a tenant. |
| **Search-only API key** | Safe to ship to browser | frontend JS | Should have only `search` (sometimes `browse`, `listIndexes`). |
| **Usage / Monitoring / Analytics keys** | Secret | server | Scoped to `usage.algolia.com`, `analytics.algolia.com`, `insights.algolia.io` — **out of this program's scope** (`.algolia.com`/`.io`, not `.net`). |
| **Secured API key** | Ships to browser per-user | frontend | HMAC-signed wrapper around a parent key with embedded restrictions (see §4). |

### 2. Host / endpoint routing — maps directly to in-scope wildcards

Algolia's REST transport is what `*.algolia.net` and `*.algolianet.com` actually resolve to:

| Purpose | Host | In scope? |
|---|---|---|
| Write / indexing / **key management** | `https://{APPID}.algolia.net` | ✅ `*.algolia.net` |
| Read / search (DSN, geo-routed) | `https://{APPID}-dsn.algolia.net` | ✅ `*.algolia.net` |
| Retry / fallback hosts | `https://{APPID}-1.algolianet.com`, `-2`, `-3.algolianet.com` | ✅ `*.algolianet.com` |

Auth is via headers `X-Algolia-Application-Id` + `X-Algolia-API-Key`, **or** query params `?x-algolia-application-id=...&x-algolia-api-key=...` (the query-param form is itself a leak vector — keys land in proxy/CDN logs and browser history).

Core endpoints:
- `POST /1/indexes/{index}/query` — single search (`search` ACL)
- `POST /1/indexes/*/queries` — multi-index batch, target `*` or a list (`search` ACL)
- `GET/POST /1/indexes/{index}/browse` — full dump (`browse` ACL)
- `GET /1/indexes` — list all indices (`listIndexes` ACL)
- `GET/PUT /1/indexes/{index}/settings` — read/write settings (`settings` / `editSettings`)
- `GET /1/logs` — recent API logs, can include other requests' data (`logs` ACL)
- `GET /1/keys`, `GET /1/keys/{key}`, `POST /1/keys`, `PUT /1/keys/{key}`, `DELETE /1/keys/{key}`, `POST /1/keys/{key}/restore` — key management (admin)

### 3. Full ACL list (VERIFIED — from `algolia/api-clients-automation` `Acl` enum)

`addObject`, `analytics`, `browse`, `deleteObject`, `deleteIndex`, `editSettings`, `inference`, `listIndexes`, `logs`, `personalization`, `recommendation`, `search`, `seeUnretrievableAttributes`, `settings`, `usage`, plus NLU/AnswersDB ACLs (`nluReadAnswers`, `nluWriteProject`, `nluReadProject`, `nluWriteEntity`, `nluReadEntity`, `nluWriteIntent`, `nluReadIntent`, `nluPrediction`).

Impact mapping for a discovered / over-privileged key:

| ACL | What it unlocks | Attacker impact |
|---|---|---|
| `search` | query | read records the tenant made searchable |
| `browse` | dump entire index bypassing pagination/query relevance | mass data exfiltration |
| `listIndexes` | enumerate all index names in the app | recon; reveals `dev_`, `staging_`, internal indices |
| `settings` / `editSettings` | read/write index settings incl. `renderingContent`, `attributesToRetrieve`, `unretrievableAttributes`, `replicas` | **stored/DOM XSS** via injected settings rendered by frontends, un-hide hidden attributes, break relevance |
| `addObject` / `deleteObject` / `deleteIndex` | write/delete records & indices | data tampering, destructive (do NOT exercise) |
| `logs` | `GET /1/logs` | read other users' recent queries/params/responses → cross-user data + key material |
| `seeUnretrievableAttributes` | return attributes listed in `unretrievableAttributes` | read PII/secrets the tenant tried to hide |
| `analytics` / `usage` / `recommendation` / `personalization` | analytics & reco data | business intelligence leakage |

### 4. Secured API keys — exact mechanism (VERIFIED from JS client source)

A secured key is **not encryption — it is a signed, base64 envelope you can fully read**. From `algoliasearch-client-javascript` (`builds/node.ts`):

```js
// generateSecuredApiKey (server-side, needs the parent key as HMAC secret)
const queryParameters = serializeQueryParameters(mergedRestrictions);  // urlencoded "filters=...&validUntil=...&restrictIndices=..."
const securedKey = Buffer.from(
  createHmac('sha256', parentApiKey).update(queryParameters).digest('hex') + queryParameters
).toString('base64');

// getSecuredApiKeyRemainingValidity — proves the payload is client-readable:
const decodedString = atob(securedApiKey);
const match = decodedString.match(/validUntil=(\d+)/);
```

So the structure is: `base64( hex(HMAC_SHA256(parentKey, qs)) [64 hex chars] + qs )`. First 64 chars of the decoded blob = signature; the rest = the human-readable restriction query string.

Restriction parameters (VERIFIED): 

| Param | Meaning | Failure mode to test |
|---|---|---|
| `validUntil` | UNIX epoch expiry | missing → **non-expiring token**; not enforced server-side → **expired-key replay** |
| `restrictIndices` | comma list / patterns (`dev_*`) of allowed indices | missing → key works on **all** app indices; pattern bypass via `*/queries` |
| `restrictSources` | allowed source IP/CIDR | missing → usable anywhere; not enforced → **IP restriction bypass** |
| `userToken` | pins a user id (analytics + rate limiting per user) | missing/spoofable → per-user rate limit / analytics abuse |
| `filters` | AND-appended security filter (e.g. `viewable_by:USERID`) | filter on non-faceted/spoofable attr, or additive-param leakage |

Two structural facts that drive the best tests:
1. **Secured keys inherit the parent key's ACLs and cannot narrow ACLs** (VERIFIED). If a developer signed with the **admin key** instead of a search key, the secured key carries admin ACLs — decode it and the ACL enumeration in §5 tells you.
2. Request-time params are **merged** with the embedded ones. `filters` are AND-combined (you cannot loosen them), **but** params like `attributesToRetrieve`, `restrictSearchableAttributes`, `hitsPerPage`, `getRankingInfo` are attacker-overridable at request time unless separately locked — so a UI-constrained secured key can be replayed with `attributesToRetrieve=["*"]` to pull fields the frontend never displays (only `unretrievableAttributes` blocks this).

### 5. Non-destructive validation methodology (safe curl PoCs)

All commands below are **read-only**. Never call `addObject`/`deleteObject`/`deleteIndex`/`PUT settings` against data you don't own — describe the ACL grant instead.

**(a) Introspect a key's own ACL, indices, and restrictions.** A key can read *itself* via `GET /1/keys/{key}` (required ACL: `search`; for a non-admin key the `description` is `<redacted>` but `acl`/`indexes`/`validity`/`maxHitsPerQuery`/`referers` are returned):

```bash
curl -s "https://APPID.algolia.net/1/keys/KEY" \
  -H "X-Algolia-Application-Id: APPID" \
  -H "X-Algolia-API-Key: KEY" | jq
# → {"acl":["search","listIndexes",...],"indexes":["*"],"validity":0,"maxHitsPerQuery":0,...}
```
`validity:0` = never expires; `indexes:["*"]` = all indices; any ACL beyond `search` on a browser-shipped key is the finding.

**(b) Enumerate indices** (needs `listIndexes`):
```bash
curl -s "https://APPID-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: APPID" -H "X-Algolia-API-Key: KEY" | jq '.items[].name'
```

**(c) Minimal, polite search PoC** (1 hit — enough to prove read access, respects rate limits):
```bash
curl -s "https://APPID-dsn.algolia.net/1/indexes/*/queries" \
  -H "X-Algolia-Application-Id: APPID" -H "X-Algolia-API-Key: KEY" \
  -H "Content-Type: application/json" \
  -d '{"requests":[{"indexName":"INDEX","params":"query=&hitsPerPage=1"}]}' | jq '.results[0].nbHits'
```

**(d) `seeUnretrievableAttributes` leakage test.** Read the index's `unretrievableAttributes`, then search with `attributesToRetrieve=["*"]` and check whether those attributes come back for a key **lacking** `seeUnretrievableAttributes`:
```bash
# 1. what does the tenant try to hide?
curl -s "https://APPID-dsn.algolia.net/1/indexes/INDEX/settings" \
  -H "X-Algolia-Application-Id: APPID" -H "X-Algolia-API-Key: KEY" \
  | jq '{unretrievableAttributes, attributesToRetrieve}'
# 2. attempt to retrieve them anyway (URL-encoded attributesToRetrieve=["*"])
curl -s "https://APPID-dsn.algolia.net/1/indexes/INDEX/query" \
  -H "X-Algolia-Application-Id: APPID" -H "X-Algolia-API-Key: KEY" \
  -H "Content-Type: application/json" \
  -d '{"params":"query=&hitsPerPage=1&attributesToRetrieve=%5B%22%2A%22%5D"}' | jq '.hits[0]'
```
Signal: an attribute named in `unretrievableAttributes` appears in `hits` for a key without that ACL → **platform enforcement bug** (reportable to Algolia). Even without the field value, you can often *oracle* it: `filters=hiddenAttr:guessedValue` or `facetFilters` returns `nbHits>0` iff the guess matches, if the attribute is faceted.

**(e) Detect & decode a secured key** (base64 that decodes to `hex + querystring`, usually much longer than a normal 32-char key):
```bash
python3 - <<'PY'
import base64, urllib.parse
k = "SECURED_KEY_B64"
blob = base64.b64decode(k).decode()
print("sig :", blob[:64])
print("rest:", urllib.parse.unquote(blob[64:]))   # filters=..., validUntil=..., restrictIndices=..., restrictSources=...
PY
```
Weakness triage from the decoded restrictions: missing `validUntil` (non-expiring), missing `restrictIndices` (all indices), missing `restrictSources` (any IP), `filters` on a spoofable/non-faceted attribute. Then confirm the *parent* ACL scope with the §5(a) introspection call against the secured key itself.

**(f) `algolia` CLI equivalents** (read-only):
```bash
algolia profile add           # store APPID + KEY (use a test app)
algolia apikey list           # requires admin
algolia apikey get KEY        # ACL + restrictions of one key
algolia settings get INDEX    # read index settings
algolia objects browse INDEX  # dump (browse ACL) — keep small
```

### 6. TESTABLE HYPOTHESES (platform enforcement — the Algolia-reportable set)

These are *not* asserted vulnerabilities; each is a hypothesis with a confirming signal. They target Algolia's own enforcement, which is what this program pays for.

1. **ACL enforcement bypass on the edge** — a `search`-only key successfully performs a `settings`/`logs`/`browse`/write op on `{APPID}-dsn.algolia.net` or `{APPID}.algolia.net`. Signal: 200 + data for an op the key's `acl` excludes.
2. **Secured-key restriction not enforced server-side** — expired `validUntil` still returns hits; `restrictSources` IP restriction ignored from another IP; `restrictIndices` bypassed by targeting a non-listed index via `/1/indexes/*/queries` or a wildcard pattern edge case (`dev_*` matched by `dev_../prod`-style tricks).
3. **Secured-key signature scope / canonicalization** — the HMAC covers the serialized string; test parameter-smuggling/duplicate-key parsing (`filters=a&filters=b`, mixed encoding, trailing `&validUntil=`) to see whether the *applied* restriction differs from the *signed* one. Requires a controlled parent key in your own test app first to build the oracle.
4. **Cross-application (tenant) isolation** — App A's key/App ID reading App B's indices on the shared DSN. Signal: `App-Id: A` + `Api-Key: A` returning B's index/data. Critical if reproducible.
5. **`attributesToRetrieve` / `restrictSearchableAttributes` override on a constrained secured key** — pull fields the app hid client-side that were not placed in `unretrievableAttributes`.
6. **Dashboard key management authZ (`dashboard.algolia.com`)** — BOLA/IDOR on the key CRUD API: create/read/rotate/delete keys of another app or team you don't belong to; a viewer/analyst dashboard role able to reveal the admin key; team-invite privilege boundaries.
7. **Key introspection info leak** — non-admin key retrieving another key's metadata, or `description` not redacted for a non-admin caller.

### 7. Scoping caveat (critical — read before reporting)

`*.algolia.net` and `*.algolianet.com` host **customer** data. A leaked *customer* admin/search key is almost always the **customer's** misconfiguration, not an Algolia platform bug — Algolia routinely closes these as N/A and directs you to the customer's own program, and accessing that customer's records breaches the "don't access other users' data" rule. To be valid *for the Algolia program*, a credential-model finding must be a flaw in **Algolia's own enforcement or products**: the edge failing to honor an ACL/secured-key restriction (§6.1–§6.3), cross-tenant leakage (§6.4), leakage from Algolia's *own* apps/keys, or an authorization flaw in `dashboard.algolia.com` / `www.algolia.com` (§6.6). Build the oracle in **your own test application** (free tier), where you control the parent key, then look for divergence between what you signed and what the edge enforces.

