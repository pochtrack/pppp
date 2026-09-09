# Recon & attack-surface checklist

Goal: map everything the program exposes, then find the parts other hunters
missed. Stay inside authorized scope at every step.

## 1. Seed & scope
- Collect in-scope apex domains, wildcards, IP ranges, mobile apps, APIs.
- Note out-of-scope assets explicitly so tooling never touches them.
- Record any required headers (e.g. `X-Bug-Bounty: <handle>`) and rate limits.

## 2. Subdomain enumeration
- Passive: certificate transparency (crt.sh), public DNS datasets, search
  engines, wayback/CommonCrawl for historical hostnames.
- Active: brute-force with a good wordlist + resolver list (respect rate
  limits); permutation/altdns on discovered names.
- Merge, dedupe, and keep the full list — even dead names document past scope.

## 3. Resolve & probe
- Resolve to IPs; group by ASN/CDN vs. origin.
- HTTP-probe live hosts: capture status, title, tech, redirects, TLS cert
  names (cert SANs reveal more hostnames — loop back to step 2).

## 4. Fingerprint
- Server/framework/CMS and versions, WAF/CDN presence, cloud provider.
- Auth mechanism (session cookie, JWT, OAuth, SSO), API style (REST/GraphQL).
- Flag anything old/unpatched or clearly legacy — top source of easy wins.

## 5. Content & endpoint discovery
- Crawl live apps; extract links, JS files, and API endpoints from JS.
- Mine JS for hardcoded endpoints, API keys, feature flags, internal hosts.
- Directory/parameter discovery with sensible wordlists.
- Pull historical URLs (wayback) for dead-but-live endpoints and old params.

## 6. Prioritize surfaces (feeds the main loop's "Prioritize" step)
Rank by expected value:
- Newly added / recently changed scope.
- Auth, account, and multi-tenant boundaries (IDOR, priv-esc, tenant leak).
- Admin panels, internal tools, staging that leaked to prod.
- Money/PII/file-upload/import-export flows.
- Anything exposing another user's identifiers in requests/responses.

## 7. Organize findings
- One notes file per asset: endpoints touched, params, auth context, and
  every negative result (negatives narrow the next test).
- Keep raw requests/responses for anything promising — they become PoCs.

## Tooling note
Prefer the recon tools already installed in the working environment. Always
throttle to the program's rate limit, and never run active scanning against
out-of-scope hosts.
