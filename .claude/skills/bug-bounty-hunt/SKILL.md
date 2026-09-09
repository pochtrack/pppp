---
name: bug-bounty-hunt
description: >-
  End-to-end methodology for authorized bug bounty hunting on HackerOne (and
  similar platforms): pulling program scope, recon and asset discovery,
  systematic vulnerability testing, high-signal reproduction, and writing
  triage-ready reports in a consistent house style. Use when the user is
  hunting on a bug bounty program, working a scope, deciding what to test next,
  reproducing/validating a finding, or drafting a HackerOne report. Composes
  with the webapp-pentest (WSTG) skill for the actual vuln-class testing.
  ONLY for programs the user is authorized to test (public/private bounty
  scope, a pentest engagement, or their own assets).
---

# Bug Bounty Hunt

A repeatable loop for finding, validating, and reporting vulnerabilities on
authorized bug bounty programs. The goal is not "run more scanners" — it is to
spend attention where payout-per-hour is highest and to submit reports that get
triaged fast and pay full bounty.

## Authorization gate (do this first, every time)

Before touching any target, confirm it is in scope:

1. Read the program's policy page and the **structured scope** (assets marked
   *In scope* / *Eligible for bounty*). Out-of-scope assets and excluded vuln
   classes are non-negotiable — testing them can get the account banned.
2. Note the rules: allowed testing methods, rate limits, required
   `X-Bug-Bounty` / user-agent headers, whether automated scanning is allowed,
   and any "do not" list (no DoS, no social engineering, no data exfiltration
   beyond PoC, redact real PII, etc.).
3. If scope is ambiguous, ask the user which assets/targets they are cleared to
   test — do not assume. Never test a domain just because it belongs to the
   same company.

If a target is not clearly authorized, stop and ask. This skill is for
authorized testing only.

## The loop

```
scope → recon → prioritize → test → validate → report → track
```

Work one asset at a time to completion rather than shallow-scanning everything.

### 1. Scope & program intake
- Pull the program's scope and policy (see `references/hackerone-api.md` for the
  API, credentials read from env only).
- Build an asset inventory: primary domains, wildcard scopes, mobile apps,
  APIs, source repos, and any "bonus" bounty-boosted assets.
- Record the reward table and response SLAs so you can prioritize.

### 2. Recon & attack surface mapping
Follow `references/recon-checklist.md`. In short: subdomain enumeration →
resolve & probe live hosts → fingerprint tech/versions → crawl & collect
endpoints/params → find forgotten/legacy assets. The bugs live in the surface
others miss (staging, old API versions, acquired-company subdomains).

### 3. Prioritize
Pick targets by *expected value*, not novelty:
- Newly added scope / recently changed assets (fresh code = fresh bugs).
- Auth, access-control, and business-logic surfaces (IDOR, privilege
  escalation, tenant isolation) — high impact, hard for scanners, well paid.
- Anything handling money, PII, or admin functions.
Deprioritize crowded, heavily-tested surfaces unless you have a novel angle.

### 4. Test
Drive the actual vulnerability testing with the **webapp-pentest** skill (WSTG
coverage of XSS, SQLi/injection, CSRF, IDOR, auth/session, SSRF, access
control, business logic, etc.). This skill decides *what to test and in what
order*; webapp-pentest supplies the *how* for each class. Keep notes of every
endpoint touched and every negative result — negatives narrow the search.

### 5. Validate before you write
A finding is only real when you can reproduce it cleanly:
- Minimal reproduction: fewest steps, exact request/response, from a fresh
  session/account.
- Prove **impact**, not just behavior — turn "reflected input" into a working
  PoC, "IDOR" into another user's actual data (redacted).
- Determine severity with CVSS 3.1 and sanity-check against the program's own
  rating tendencies.
- Rule out duplicates/known issues and self-inflicted setups.

### 6. Report
Write it with `references/report-template.md`. A great report = fast triage =
full bounty. Lead with impact, give copy-pasteable repro steps, attach the
PoC, and state remediation. One vulnerability per report unless they chain.

### 7. Track & follow up
Log submissions, states (new/triaged/resolved/duplicate), and payouts. Feed
resolved reports back into your own playbook (see Personalization below).

## Personalize from past reports

This skill ships with a strong *default* methodology and report style. To make
it hunt "your way", feed in your own history:

1. Provide past reports — export from HackerOne, or paste a handful of
   representative resolved ones (redact any live PII/secrets first).
2. Ask Claude to extract *your* patterns: which vuln classes you land most,
   your recon shortcuts, your report structure and tone, your severity
   framing, and phrasings that got fast triage.
3. Claude updates `references/report-template.md` and this file's Prioritize /
   Test sections to match your proven approach.

Until then, treat the defaults here as a starting playbook, not a fixed one.

## Reference files
- `references/recon-checklist.md` — asset discovery and attack-surface mapping.
- `references/report-template.md` — the house-style HackerOne report format.
- `references/hackerone-api.md` — reading scope and reports via the H1 API,
  with credentials sourced from environment variables only.

## Hard rules
- Authorized scope only. Respect every program rule and rate limit.
- Never store API tokens, session cookies, or credentials in files, commits,
  code, or reports. Read them from environment variables (`H1_API_USERNAME`,
  `H1_API_TOKEN`) at runtime.
- Impact PoCs only — access the minimum needed to prove the bug; never
  exfiltrate real user data, pivot, persist, or degrade service.
- Redact real PII/secrets from reports and attachments.
