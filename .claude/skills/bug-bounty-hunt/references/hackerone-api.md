# HackerOne API access

Read program scope and your own reports programmatically. **Credentials come
from environment variables only — never hardcode, never commit, never paste a
token into a report, file, or chat.**

## Credentials

Set once in your shell/session environment:

```bash
export H1_API_USERNAME="your-api-identifier"
export H1_API_TOKEN="your-api-token"   # rotate at hackerone.com/settings/api_token/edit
```

Auth is HTTP Basic: `-u "$H1_API_USERNAME:$H1_API_TOKEN"`.

If a token has ever appeared in plaintext (chat, logs, a file), treat it as
compromised and rotate it immediately.

## Common calls (Hacker API)

List your reports:
```bash
curl -sS -g -u "$H1_API_USERNAME:$H1_API_TOKEN" \
  -H "Accept: application/json" \
  "https://api.hackerone.com/v1/hackers/me/reports?page%5Bsize%5D=100"
```

Get one report:
```bash
curl -sS -u "$H1_API_USERNAME:$H1_API_TOKEN" \
  -H "Accept: application/json" \
  "https://api.hackerone.com/v1/hackers/reports/<REPORT_ID>"
```

Program structured scope (confirm what is in scope before testing):
```bash
curl -sS -g -u "$H1_API_USERNAME:$H1_API_TOKEN" \
  -H "Accept: application/json" \
  "https://api.hackerone.com/v1/hackers/programs/<HANDLE>/structured_scopes?page%5Bsize%5D=100"
```

Notes:
- `[` / `]` in query params must be URL-encoded (`%5B`/`%5D`) or curl needs
  `-g` (globoff), or curl treats `[` as a range and errors.
- Paginate via the `links.next` URL in each response.
- Respect API rate limits.

## Network reachability

`api.hackerone.com` must be reachable from wherever the session runs. In a
sandboxed/cloud environment with an egress allowlist, the request can be
rejected by the proxy (e.g. HTTP 403 on CONNECT) even with a valid token — that
is a network-policy block, not an auth failure. Options: allowlist
`api.hackerone.com` in the environment's network policy, run locally where H1 is
reachable, or work from exported/pasted reports instead.
