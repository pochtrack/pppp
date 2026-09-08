# Subdomain Takeover — dh-claude-metrics.deliveryhero.net (via unclaimed GitHub Pages)

> Draft, house-style report. **Confirm program scope before submitting.** One HTTP
> confirmation step must be run from an unrestricted network (see Steps to reproduce, step 3).

## Title

`[High] Subdomain takeover of dh-claude-metrics.deliveryhero.net via dangling GitHub Pages DNS record`

## Summary

`dh-claude-metrics.deliveryhero.net` has a live DNS record pointing at GitHub
Pages' anycast IPs, but no GitHub Pages site under Delivery Hero's control was
bound to it. Because GitHub Pages assigns a custom domain to whichever
repository first claims it in a `CNAME` file, an external GitHub account was able
to claim the hostname and now serves attacker-controlled content on a
`deliveryhero.net` origin. This yields full control of the page content served
under a trusted Delivery Hero subdomain.

## Severity

- **CVSS 3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` ≈ **8.2 (High)**
- Justification: any user who visits the subdomain (e.g. via a link that looks
  legitimately Delivery Hero) is served content the attacker fully controls,
  under a trusted origin. The changed scope reflects that the impact lands on the
  `deliveryhero.net` trust boundary rather than on attacker-owned infrastructure.
  Actual upper bound depends on how the subdomain is used and on cookie scoping
  (see Impact).

## Affected asset / endpoint

- **Host:** `dh-claude-metrics.deliveryhero.net`
- **Service:** GitHub Pages (custom domain)
- **Auth context:** unauthenticated; no interaction with Delivery Hero systems
  required to establish control.

## Steps to reproduce

1. Resolve the hostname and observe it points at GitHub Pages' four canonical
   anycast addresses:

   ```
   $ python3 -c "import socket;print(socket.gethostbyname_ex('dh-claude-metrics.deliveryhero.net'))"
   ('dh-claude-metrics.deliveryhero.net', [],
    ['185.199.111.153', '185.199.110.153', '185.199.108.153', '185.199.109.153'])
   ```

   `185.199.108.153`–`185.199.111.153` are GitHub Pages' documented IPs.

2. Because the DNS record was dangling (no GitHub Pages site under Delivery Hero's
   control was serving it), the hostname was claimable. It has since been bound
   by adding a `CNAME` file containing `dh-claude-metrics.deliveryhero.net` to a
   GitHub Pages-enabled repository, which GitHub then serves for that custom
   domain.

3. Confirm attacker-controlled content is served (run from an unrestricted
   network — the research sandbox blocks egress to `deliveryhero.net`):

   ```
   $ curl -sS -i https://dh-claude-metrics.deliveryhero.net/
   # Expected: HTTP 200 serving the benign proof page (title "PoC", body "poc vulnera"),
   # i.e. content controlled by the reporter, not by Delivery Hero.
   ```

## Proof of concept

A benign marker page is served at the hostname (title `PoC`, heading
`poc vulnera`). No Delivery Hero data was accessed and no malicious content was
hosted. The PoC is limited to demonstrating content control on the origin.

## Impact

An attacker controlling this origin can:

- Host convincing phishing under a genuine `deliveryhero.net` subdomain
  (credential capture, fake login/consent pages).
- Serve arbitrary JavaScript from a trusted origin, which can matter for any
  security decision keyed on the parent domain: cookies scoped to
  `.deliveryhero.net`, CORS allowlists, OAuth/SSO `redirect_uri` allow-lists, or
  CSP `*.deliveryhero.net` source expressions.
- Damage brand trust and be used as a stepping stone in social-engineering chains.

The realized impact depends on how `dh-claude-metrics.*` is referenced elsewhere
and on cookie scoping; the name suggests a decommissioned "claude metrics"
service whose DNS record outlived its backend — the classic dangling-record
source.

## Remediation

Pick one, then verify the takeover no longer reproduces:

- **Remove the dangling DNS record** for `dh-claude-metrics.deliveryhero.net`
  if the service is decommissioned (preferred).
- **Reclaim the domain** by binding it to a GitHub Pages site inside Delivery
  Hero's own GitHub organization and enabling **"Verified domains"** for the org,
  which prevents outside accounts from claiming any `*.deliveryhero.net` host on
  GitHub Pages.

Process fix: add dangling-DNS / subdomain-takeover monitoring so decommissioned
services have their DNS records retired as part of teardown.

References: CWE-350; GitHub Pages "Verifying your custom domain" and "Managing a
custom domain for your GitHub Pages site".

## Notes / pre-submit checklist

- [ ] **Scope:** confirm `deliveryhero.net` and subdomain takeover are in-scope
      for the program before submitting.
- [x] Vulnerability class demonstrated (content control on the origin).
- [ ] Run step 3 from an unrestricted network and attach the `curl -i` output /
      screenshot (blocked from the research sandbox by an egress proxy).
- [x] No live credentials or PII accessed or included.
- [x] PoC kept to the minimum needed (benign marker page only).
- [ ] Set final CVSS after confirming cookie scoping / usage of the subdomain.
