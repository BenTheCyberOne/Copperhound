# Deploying CopperHound

Running the server, accounts and automation, notifications, HTTPS and single
sign-on. For a first run see the [README quick start](../README.md#quick-start-docker).

## Running

`COPPERHOUND_ADMIN_PASSWORD` sets the initial admin password, and
`COPPERHOUND_PORT` / `COPPERHOUND_HOST` change the published address (default
`127.0.0.1:8090`, so it can run next to BloodHound on 8080).

Without Docker: `cd web && npm ci && npm run build`, then
`cargo run --release -- serve` (defaults: `127.0.0.1:8080`, data in `./data`,
UI from `./web/dist`).

## Users and automation

Create `viewer` / `analyst` / `admin` accounts under
**Admin → Users**; every change is recorded in the **audit log**. Personal API
tokens (`cht_…`) authenticate scripts and CI. **Auto-ingest:** enable the watch
folder (**Admin → Settings**, or `COPPERHOUND_WATCH_DIR`) and drop collector
output into it; CopperHound waits for the files to finish copying, ingests them
and records a posture snapshot. **Reports:** HTML / Markdown / CSV assessment
reports from the UI, `GET /api/v1/report` or `copperhound report`.

## Scheduled reports and change alerts

Admins configure notification channels
(generic JSON webhook with optional HMAC-SHA256 signature, Slack, Microsoft Teams,
and SMTP email with STARTTLS or implicit TLS, rustls only) and schedule reports
daily or weekly at a UTC time, or every N hours. A report posts the posture
grade, exposure, top findings and the change since the last snapshot; emails
attach the full report. After every ingest CopperHound compares the new posture
with the previous one and alerts on the rules you choose: grade got worse,
exposure up by X points, new critical/high findings, N or more principals newly
able to reach Tier Zero, a watched user or group gaining a path to Tier Zero
(the alert carries the path and draws it), or changed choke points. Set
`COPPERHOUND_PUBLIC_URL` to include a link back to the UI. See
[docs/API.md](API.md#5-reports-notifications-schedules-and-alerts).

## HTTPS

CopperHound can terminate TLS itself with rustls, no proxy needed.
`COPPERHOUND_TLS=self-signed` generates a certificate into the data volume
(extra names in `COPPERHOUND_TLS_HOSTNAMES`); alternatively, point
`COPPERHOUND_TLS_CERT` / `COPPERHOUND_TLS_KEY` at PEM files, and renewed files
are picked up within 30 s. With TLS on, responses carry HSTS and generated URLs
(SSO redirect, SAML ACS) use `https`. SAML sign-in requires HTTPS.

## Single sign-on (OpenID Connect)

CopperHound signs users in through any OIDC provider (Entra ID, Okta, Keycloak,
Google, …) using the authorization-code flow with PKCE. Accounts are created on
first sign-in, and their role (`viewer` / `analyst` / `admin`) is taken from IdP
groups or app roles on every sign-in. Configure it under **Admin → Settings → Single sign-on**
(`/api/v1/settings/sso`) or with environment variables. Register this redirect URI
at the IdP:

```
https://<your CopperHound host>/api/v1/auth/oidc/callback
```

Behind a reverse proxy set `COPPERHOUND_PUBLIC_URL=https://copperhound.corp.example`
(or `COPPERHOUND_OIDC_REDIRECT_URL`) so the redirect URI is exact.

**Entra ID** — App registrations → New registration, platform *Web*, redirect URI as
above; Certificates & secrets → new client secret. For roles, either add *App roles*
(e.g. `CopperHound.Admin`, `CopperHound.Analyst`) and assign users/groups under
Enterprise applications, or Token configuration → *Add groups claim* (security
groups; use object IDs). Use the tenant-specific issuer (`common` /
`organizations` are not supported):

```yaml
environment:
  COPPERHOUND_OIDC_ISSUER: https://login.microsoftonline.com/<tenant-id>/v2.0
  COPPERHOUND_OIDC_CLIENT_ID: <application (client) id>
  COPPERHOUND_OIDC_CLIENT_SECRET: <client secret value>
  COPPERHOUND_OIDC_GROUPS_CLAIM: groups,roles
  COPPERHOUND_OIDC_ADMIN_GROUPS: CopperHound.Admin,<admin group object id>
  COPPERHOUND_OIDC_ANALYST_GROUPS: CopperHound.Analyst
  COPPERHOUND_OIDC_DEFAULT_ROLE: viewer      # or deny (default)
  COPPERHOUND_PUBLIC_URL: https://copperhound.corp.example
```

Users in more than ~200 groups get no `groups` claim (overage) — prefer app roles,
or "Groups assigned to the application".

**Keycloak** — Clients → Create client, *OpenID Connect*, client authentication
on, standard flow on, valid redirect URI as above. Add a *Group Membership* mapper
(token claim name `groups`, *Full group path* off, *Add to ID token* on), or map
realm roles with `COPPERHOUND_OIDC_GROUPS_CLAIM=realm_access.roles` after enabling
*Add to ID token* on the `realm roles` mapper:

```yaml
environment:
  COPPERHOUND_OIDC_ISSUER: https://keycloak.corp.example/realms/corp
  COPPERHOUND_OIDC_CLIENT_ID: copperhound
  COPPERHOUND_OIDC_CLIENT_SECRET: <credentials tab>
  COPPERHOUND_OIDC_ADMIN_GROUPS: copperhound-admins
  COPPERHOUND_OIDC_ANALYST_GROUPS: copperhound-analysts
  COPPERHOUND_OIDC_VIEWER_GROUPS: copperhound-viewers
  # COPPERHOUND_OIDC_CA_FILE: /data/corp-ca.pem   # internal CA
```

**Google** (issuer `https://accounts.google.com`) emits no groups claim: restrict
sign-in with `COPPERHOUND_OIDC_ALLOWED_EMAIL_DOMAINS=corp.example` and set
`COPPERHOUND_OIDC_DEFAULT_ROLE=viewer` (or `analyst`). Since roles are re-evaluated
on every sign-in, keep admin work on local accounts in that case.
**Okta**: issuer `https://<org>.okta.com` (or `…/oauth2/default`), add a *groups*
claim to the ID token in the app's sign-on settings.

**Break-glass.** The built-in `admin` keeps password sign-in unless you set both
`allow_password_login: false` and `disable_admin_password_login: true`. The latter
is only accepted, and only enforced, once an SSO account with the admin role has
successfully signed in. If the IdP is down, start with
`COPPERHOUND_SSO_BREAK_GLASS=1`. Every SSO sign-in, failure (with reason) and
configuration change is in the audit log. Details: [docs/API.md](API.md#openid-connect).

## Single sign-on (SAML 2.0)

For IdPs without OIDC (AD FS, Shibboleth, PingFederate, …) CopperHound also acts
as a SAML 2.0 service provider (Admin → SSO → SAML 2.0). Paste the IdP's metadata
XML, register the shown SP entity ID and ACS URL (or the SP metadata URL
`/api/v1/auth/saml/metadata`) at the IdP, and map group attribute values to
roles as for OIDC. Sign-in is SP-initiated (HTTP-Redirect request, HTTP-POST
response); unsolicited (IdP-initiated) responses are refused.

Responses are verified in pure Rust (no libxml2 / xmlsec): exclusive C14N,
enveloped RSA-SHA256/384/512 signatures on the response or the assertion with
the metadata's certificates only, `InResponseTo`, destination, issuer,
audience, bearer confirmation and validity window, one-time assertion IDs, no
DTDs, and signature-wrapping defences (a signature only counts for its own
parent element, IDs must be unique, exactly one assertion). SHA-1 and encrypted
assertions are not accepted. The verifier is tested against responses signed
with libxml2's canonicalisation (`crates/server/tests/fixtures/saml/gen.py`),
including tampered, wrapped and wrong-key ones. HTTPS (or `localhost`) is
required because the IdP's POST is cross-site and the sign-in cookie is
`SameSite=None; Secure`.
