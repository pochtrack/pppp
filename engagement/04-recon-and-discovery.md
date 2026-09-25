# 04 — Recon, Content-Discovery & Automation Pipeline

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware.

---

## Facet: Recon, Content-Discovery & Automation Pipeline — Algolia (scoped)

This section turns the four in-scope assets into a copy-pasteable pipeline. It is tuned to Algolia's *specific* architecture and to the program's "no scanner-only reports / minimal PoC / own test accounts" rules. Every host, path, header and ACL below is a **verified public fact**; everything about a live vuln is framed as a **testable hypothesis**.

### 0. Scope model — and the one distinction that makes or breaks this program

| Asset | Type | What it actually is |
|---|---|---|
| `*.algolia.net` | wildcard | Search/indexing REST-API DSN infra: `{APPID}-dsn.algolia.net`, `{APPID}-1/2/3.algolia.net` |
| `*.algolianet.com` | wildcard | Fallback/retry API + CDN hosts: `{APPID}-1/2/3.algolianet.com` |
| `dashboard.algolia.com` | URL | Customer dashboard web app |
| `www.algolia.com` | URL | Marketing/main site |

**The trap:** the two wildcards are *multi-tenant search infrastructure*. A host like `XY1234ABCD-dsn.algolia.net` is a DNS label pointing at a **shared cluster** that hosts *many customers'* indices. If you point an exposed key at some random customer's `{APPID}` host and dump their catalog, you have found **the customer's** misconfiguration, not Algolia's — that class is (a) not Algolia's asset, (b) capped at "minimal PoC / do not access other users' data", and (c) the single most-duplicated Algolia report class on the internet. **It will be closed N/A or Informative.**

The reportable-to-Algolia surface on the wildcards is the **platform/software running on those hosts** — cross-tenant isolation breaks, ACL bypasses, injection into the engine, response-splitting/cache issues, auth handling — which you must reproduce against **your own free Algolia application's `{APPID}`** so no other tenant's data is touched. Treat the wildcards as "the API software", not "other people's indices".

**Owned-infra vs multi-tenant bucketing (observed live 2026-09-25 — IPs rotate, re-verify):**

| Host | Resolves to | Provider / CNAME chain | Bucket |
|---|---|---|---|
| `latency-dsn.algolia.net` | 149.28.246.96 | Vultr; alias `s7-usc-1.algolia.net`, `dsn.latency.api.algolia.net` | multi-tenant search node |
| `latency-1.algolianet.com` | 141.95.34.183 | OVH; alias `c50-eu-1.algolianet.com` | multi-tenant search node (retry ring) |
| `dashboard.algolia.com` | 104.17.255.197 | **Cloudflare** | Algolia-owned web app |
| `www.algolia.com` | 104.17.255.197 | **Cloudflare** | Algolia-owned web |
| `analytics.algolia.com` | 104.17.255.197 | **Cloudflare** | Algolia-owned web (adjacent, confirm scope) |
| `insights.algolia.io` | 34.96.91.250 | GCP; alias `insights.us.algolia.io` | Algolia-owned API (`.io`, out of this scope) |
| `places-dsn.algolia.net` | NXDOMAIN | — | sunset product (Places retired) |

**Recon rule of thumb:** an `*.algolia.net`/`*.algolianet.com` label whose CNAME/PTR is a **cluster pattern** (`sN-<region>-N`, `cNN-<region>-N`) on Vultr/OVH/AWS = shared search node (customer-data territory, low Algolia value). A label that is **not** `{APPID}-...` and points at **Cloudflare / GCP / an Algolia-owned corp IP** = a service/console/internal host and is where the interesting Algolia-owned bugs live. The whole enumeration below is built to surface that second bucket.

> Note on `*.algolia.com`: only `www` and `dashboard` are listed as URL assets in this scope. Historically-disclosed takeovers were on other `*.algolia.com` labels (`prestashop.`, `recommendation.`) — **confirm on the live policy page before touching any other `algolia.com` host**; it may be out of scope now.

### 1. One-time setup

```bash
# Go tools (ProjectDiscovery + friends)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/owasp-amass/amass/v4/...@master
pipx install arjun

WORK=~/algolia-recon && mkdir -p "$WORK"/{raw,live,js,urls,params,nuclei} && cd "$WORK"
printf 'algolia.net\nalgolianet.com\n' > wildcards.txt
printf 'dashboard.algolia.com\nwww.algolia.com\n' > urlhosts.txt
# trustworthy resolvers for puredns/dnsx (avoid your ISP resolver poisoning results)
printf '1.1.1.1\n8.8.8.8\n9.9.9.9\n' > resolvers.txt
```

### 2. Passive subdomain + CT enumeration (the two wildcards)

Passive first — no packets at Algolia. crt.sh, subfinder's sources, and CT aggregators.

```bash
# subfinder across all passive sources
subfinder -dL wildcards.txt -all -silent -o raw/subfinder.txt

# amass passive (no active brute here — stay quiet)
amass enum -passive -df wildcards.txt -o raw/amass.txt

# crt.sh direct (both wildcards) — pull SANs, split multiline, dedup
for d in algolia.net algolianet.com; do
  curl -s "https://crt.sh/?q=%25.$d&output=json" \
    | jq -r '.[].name_value' 2>/dev/null
done | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' | sort -u > raw/crtsh.txt

# certspotter (second CT source, different coverage)
for d in algolia.net algolianet.com; do
  curl -s "https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names" \
    | jq -r '.[].dns_names[]' 2>/dev/null
done | sed 's/^\*\.//' | sort -u >> raw/crtsh.txt

cat raw/*.txt | grep -Ei '\.(algolia\.net|algolianet\.com)$' | sort -u > raw/all_subs.txt
wc -l raw/all_subs.txt
```

> If `crt.sh` times out from your egress (it rate-limits hard), use `github.com/az7rb/crt.sh`, the certspotter API above, or `curl 'https://otx.alienvault.com/api/v1/indicators/domain/algolia.net/passive_dns'`.

### 3. Resolve, kill wildcard DNS, fingerprint, then **bucket**

```bash
# resolve + capture A + CNAME + ASN in one pass; this is where owned-vs-tenant gets decided
dnsx -l raw/all_subs.txt -r resolvers.txt -a -cname -asn -resp -silent -o live/resolved.txt

# BUCKET A — likely Algolia-owned services (NOT {APPID}-pattern, not a cluster node):
grep -viE '^[a-z0-9]{6,}-(dsn|[0-9]+)\.' live/resolved.txt \
  | grep -viE 'c[0-9]+-[a-z]{2,3}-[0-9]|s[0-9]+-[a-z]{2,4}-[0-9]' \
  > live/owned_candidates.txt

# BUCKET B — multi-tenant search nodes / customer DSN (deprioritize; customer-data territory).
#   This is simply the complement of Bucket A (the {APPID}-dsn / {APPID}-N / cluster-node hosts).
#   Do NOT hand-test these; they carry other customers' data (out of Algolia's asset + saturated dup class):
comm -23 <(awk '{print $1}' live/resolved.txt | sort -u) \
         <(awk '{print $1}' live/owned_candidates.txt | sort -u) > live/tenant_hosts.txt

# liveness + tech + title + CDN on the owned candidates only, POLITE
httpx -l live/owned_candidates.txt -rl 25 -t 20 -follow-redirects \
  -sc -title -tech-detect -cdn -server -location -json -o live/owned_httpx.json

# the two URL hosts get first-class treatment
httpx -u https://dashboard.algolia.com -u https://www.algolia.com \
  -sc -title -tech-detect -server -json -o live/urlhosts_httpx.json
```

What you're hunting in Bucket A: a `staging-*`, `internal-*`, `admin-*`, `*-status`, `metabase-*`, `grafana-*`, `sentry-*`, old-product (`places`, `recommend`, `crawler`) label on the wildcards that answers with something that is **not** the standard search-API 403/`{"message":"..."}` JSON. Any `NXDOMAIN`/`SERVFAIL` label with a dangling `CNAME` to a deprovisioned SaaS is your **subdomain-takeover** candidate (see test idea #1).

### 4. JS analysis of `dashboard.algolia.com` & `www.algolia.com`

Extract API endpoints, internal app IDs, and **your own** keys / secrets accidentally shipped to the client.

```bash
# Crawl + collect every JS asset (headless, polite)
katana -u https://dashboard.algolia.com -u https://www.algolia.com \
  -jc -kf all -d 3 -rl 20 -c 10 -aff -silent \
  -em js,json,map -o urls/katana_js.txt

# also grab historic JS from wayback/gau, then filter to js
cat urls/katana_js.txt <(gau --subs dashboard.algolia.com www.algolia.com) \
  | grep -Ei '\.js(\?|$)|\.map(\?|$)' | sort -u > js/jsurls.txt

# download JS
mkdir -p js/files && while read u; do
  fn=$(echo "$u" | md5sum | cut -c1-16); curl -s --max-time 20 "$u" -o "js/files/$fn.js"
done < js/jsurls.txt

# --- pull Algolia-specific secrets / endpoints out of the JS ---
cd js/files
# Application IDs (assigned IDs are ~10 uppercase alnum; 'latency' demo is lowercase — keep both patterns)
grep -rhoE '(applicationID|appId|app_id|x-algolia-application-id)["'"'"' :=]+[A-Z0-9]{6,12}' . | sort -u
grep -rhoE '\b[A-Z0-9]{10}\b' . | sort -u | head          # candidate app IDs (verify)
# API keys: search/admin keys are 32-char lowercase hex; secured keys are long base64
grep -rhoE '(apiKey|api_key|x-algolia-api-key)["'"'"' :=]+[a-f0-9]{32}' . | sort -u
grep -rhoE '\b[a-f0-9]{32}\b' . | sort -u | head          # candidate keys (verify ACL, see §9)
# raw endpoint strings and the header names
grep -rhoE 'https?://[a-z0-9.-]*algolia(net)?\.(com|net|io)[^"'"'"' ]*' . | sort -u
grep -rhiE 'x-algolia-(api-key|application-id|agent|usertoken)' . | sort -u
# source maps → recover original TS/JSX (endpoints, internal routes, feature flags)
grep -rhoE 'sourceMappingURL=.*\.map' .
cd "$WORK"
```

Interpretation: any `[a-f0-9]{32}` key you extract that is **not** clearly a search-only key (test its ACL in §9) shipped in `dashboard.algolia.com`/`www.algolia.com` client JS is a genuine Algolia-owned exposure — that is the write-up, not a random customer's key on cdn.example.com.

### 5. Historical URL mining

```bash
# All four assets. --subs so we catch any labels under algolia.com too.
gau --subs algolia.com          | grep -Ei 'dashboard\.algolia\.com|www\.algolia\.com' > urls/gau.txt
echo -e "dashboard.algolia.com\nwww.algolia.com" | waybackurls        >> urls/gau.txt
# katana passive against wayback/commoncrawl for the wildcards' owned hosts
katana -list live/owned_candidates.txt -passive -silent -o urls/katana_passive.txt

sort -u urls/gau.txt urls/katana_passive.txt > urls/all_urls.txt
# quick wins: deprecated endpoints, secrets in query strings, old API params
grep -Ei '\.(json|xml|yaml|env|bak|old|log|sql|zip)(\?|$)' urls/all_urls.txt
grep -Ei '(api|graphql|internal|admin|debug|token|key|signature|jwt)=' urls/all_urls.txt
grep -Ei '/1/(indexes|keys|settings|logs|clusters|usage)' urls/all_urls.txt
```

### 6. Parameter discovery (dashboard API + www)

```bash
# gf patterns to triage collected URLs before active fuzzing
gf ssrf urls/all_urls.txt; gf redirect urls/all_urls.txt; gf idor urls/all_urls.txt

# arjun for hidden params on dashboard's JSON/API routes (find these in §4/§5 first)
arjun -u "https://dashboard.algolia.com/api/1/<route-from-js>" -m GET,POST \
  --rate-limit 20 -oT params/arjun_dashboard.txt
```

### 7. Polite content discovery (owned hosts only — never the tenant DSN hosts)

```bash
ffuf -u https://dashboard.algolia.com/FUZZ -w algolia-wordlist.txt \
  -mc 200,204,301,302,307,401,403,405 -ac -rate 25 -t 10 \
  -H "User-Agent: bugbounty-<yourh1handle> (authorized H1 testing)" -o params/ffuf_dash.json
# feroxbuster alternative with built-in throttling
feroxbuster -u https://www.algolia.com -w algolia-wordlist.txt \
  --rate-limit 25 -t 10 -s 200,204,301,302,401,403 -o params/ferox_www.txt
```

### 8. nuclei — SURFACE candidates, never auto-report

Per program rules, **raw scanner output is not reportable**. Use nuclei only to flag candidates you will then hand-verify and hand-write.

```bash
# Only owned hosts. Politeness: low rate, low bulk/concurrency, retries, timeout.
nuclei -l live/owned_candidates.txt \
  -t http/takeovers/ -t http/cves/ -t http/misconfiguration/ \
  -t http/exposures/ -t http/cors/ \
  -et http/fuzzing/ \
  -rl 30 -c 15 -bs 15 -retries 1 -timeout 8 \
  -H "User-Agent: bugbounty-<yourh1handle> (authorized H1 testing)" \
  -severity low,medium,high,critical -stats -o nuclei/owned.txt

# The two URL hosts, same politeness
nuclei -u https://dashboard.algolia.com -u https://www.algolia.com \
  -t http/takeovers/ -t http/cors/ -t http/misconfiguration/ -t http/exposures/ \
  -rl 20 -c 10 -bs 10 -o nuclei/urlhosts.txt
```

Template picks that matter for Algolia: `takeovers` (dangling CNAMEs — historically Algolia's most-hit class), `cors` (dashboard API reflecting `Origin` with creds), `exposures/configs` (`.env`, `.git`, source maps, PHP-FPM/`server-status` — a PHP-FPM status disclosure was a real Algolia report), `misconfiguration`. **Skip `-severity info` for reporting** and never paste the nuclei line as a report body.

### 9. Probing the API *platform* with YOUR OWN app (the wildcards' real surface)

Create a free Algolia app → you get **your own** `{APPID}` + Admin/Search keys. All requests below hit **your** tenant only. Headers/paths are the documented REST API.

```bash
APPID=YOUR_OWN_APPID; ADMIN=YOUR_ADMIN_KEY; SEARCH=YOUR_SEARCH_KEY
H=(-H "x-algolia-application-id: $APPID")

# key ACL introspection — what does a given key actually allow?
curl -s "https://$APPID-dsn.algolia.net/1/keys/$SEARCH" "${H[@]}" -H "x-algolia-api-key: $ADMIN" | jq .

# list indices (needs listIndexes ACL) — the classic misconfig probe, but on YOUR data
curl -s "https://$APPID-dsn.algolia.net/1/indexes/" "${H[@]}" -H "x-algolia-api-key: $SEARCH" | jq '.items[].name'

# browse a whole index (needs browse ACL)
curl -s -X POST "https://$APPID-dsn.algolia.net/1/indexes/YOURINDEX/browse" "${H[@]}" -H "x-algolia-api-key: $SEARCH"

# health / node probe
curl -s "https://$APPID-dsn.algolia.net/1/isalive" "${H[@]}" -H "x-algolia-api-key: $SEARCH"

# HYPOTHESIS TESTS worth doing against your own app + a 2nd own app:
#  - can a search-only key from app A ever return data for app B's {APPID}? (tenant isolation)
#  - does the engine reflect injected HTML in highlight tags cross-user? (settings highlightPreTag)
#  - CORS on the API host with a random Origin + credentials:
curl -s -i "https://$APPID-dsn.algolia.net/1/indexes/" "${H[@]}" -H "x-algolia-api-key: $SEARCH" \
     -H "Origin: https://evil.example" | grep -i 'access-control'
```

### 10. Rate-limit & politeness hygiene

- Algolia's API clients treat repeated failures as "host down" and rotate through the retry ring; **hammering `{APPID}` hosts looks like the abuse the program's DDoS exclusion covers.** Keep httpx `-rl ≤ 25`, ffuf `-rate ≤ 25 -t 10`, nuclei `-rl ≤ 30 -c ≤ 15 -bs ≤ 15`.
- Set an identifying `User-Agent` with your H1 handle so Algolia can attribute traffic.
- Never run active brute-force DNS or ffuf against the `{APPID}-*` tenant hosts — that is customer infra + volumetric noise.
- A single `429` = back off; do not tune around it (missing-rate-limit reports are excluded, and evading them is bad-faith).
- Keep PoCs to **your own** app IDs / a single record. "Minimal PoC" is a hard program rule.

### Algolia-specific wordlist (`algolia-wordlist.txt`)

```
# --- REST API paths (version-prefixed) ---
1/indexes
1/indexes/*
1/keys
1/keys/*
1/settings
1/logs
1/clusters
1/clusters/mapping
1/clusters/mapping/top
1/clusters/mapping/pending
1/task
1/isalive
1/indexes/*/settings
1/indexes/*/browse
1/indexes/*/query
1/indexes/*/queries
1/indexes/*/batch
1/indexes/*/rules
1/indexes/*/rules/search
1/indexes/*/synonyms
1/indexes/*/synonyms/search
1/indexes/*/operation
1/dictionaries/*/batch
1/dictionaries/*/search
1/dictionaries/*/settings
1/answers/*/prediction
2/abtests
1/usage
1/status
# --- likely-index names (self-owned test app; also seen in the wild) ---
prod
production
staging
dev
users
products
articles
posts
docs
documentation
content
search
pages
customers
orders
# --- dashboard / web app routes ---
account
account/api-keys
account/security
account/billing
users
teams
apps
dashboard
explorer
analytics
monitoring
insights
recommend
crawler
crawlers
query-suggestions
api-keys
settings
onboarding
login
logout
sso
saml
oauth
oauth/callback
graphql
api
api/1
internal
admin
debug
health
status
server-status
.env
.git/config
.well-known/security.txt
```

### Full orchestration (glue script)

```bash
#!/usr/bin/env bash
set -euo pipefail
cd ~/algolia-recon
UA="bugbounty-<yourh1handle> (authorized H1 testing)"
# 1 passive subs
subfinder -dL wildcards.txt -all -silent > raw/subfinder.txt
for d in algolia.net algolianet.com; do
  curl -s "https://crt.sh/?q=%25.$d&output=json" | jq -r '.[].name_value' 2>/dev/null
done | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | sort -u > raw/crtsh.txt
cat raw/*.txt | grep -Ei '\.(algolia\.net|algolianet\.com)$' | sort -u > raw/all_subs.txt
# 2 resolve + bucket
dnsx -l raw/all_subs.txt -r resolvers.txt -a -cname -asn -resp -silent -o live/resolved.txt
grep -viE '^[a-z0-9]{6,}-(dsn|[0-9]+)\.' live/resolved.txt \
  | grep -viE 'c[0-9]+-[a-z]{2,3}-[0-9]|s[0-9]+-[a-z]{2,4}-[0-9]' \
  | awk '{print $1}' | sort -u > live/owned_candidates.txt
# 3 fingerprint owned + the two url hosts
{ cat live/owned_candidates.txt; echo dashboard.algolia.com; echo www.algolia.com; } | sort -u \
  | httpx -rl 25 -t 20 -sc -title -tech-detect -cdn -server -json -o live/httpx.json
# 4 nuclei SURFACE (verify by hand before any report)
nuclei -l live/owned_candidates.txt -u https://dashboard.algolia.com -u https://www.algolia.com \
  -t http/takeovers/ -t http/cors/ -t http/misconfiguration/ -t http/exposures/ -t http/cves/ \
  -rl 30 -c 15 -bs 15 -H "User-Agent: $UA" -severity low,medium,high,critical -o nuclei/all.txt
echo "Review live/httpx.json + nuclei/all.txt by hand. Nothing here is a report until manually verified."
```

