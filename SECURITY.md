# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/BenTheCyberOne/Copperhound/security/advisories/new>).
Do not open a public issue for security problems.

Include what you can of:

- the affected component (server API, authentication / SSO, ingest parsers, web UI, CLI);
- the version or commit;
- steps to reproduce, or a proof of concept;
- the impact you expect.

We aim to acknowledge reports within a week. Once a fix is released, we publish an
advisory crediting you, unless you prefer not to be named.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Scope

In scope, for example:

- authentication or authorisation bypass, including OIDC, SAML, 2FA, API tokens and
  `CH-HMAC` request signing;
- privilege escalation between roles (`uploader`, `viewer`, `analyst`, `admin`);
- remote code execution, path traversal or file overwrite through uploads or ingest;
- server-side request forgery through notification channels, ticketing targets or
  collectors;
- cross-site scripting or injection in the web UI or generated reports;
- crashes or memory exhaustion from small crafted inputs.

Out of scope:

- the attack paths CopperHound shows in your directory data; those are findings
  about the analysed environment, not vulnerabilities in CopperHound;
- issues that need an `admin` account to misconfigure the server against itself;
- running the server exposed to untrusted networks without TLS, against the
  deployment guidance in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

CopperHound is for assessing environments you are authorised to assess. Please test
against your own instance and fabricated data (`scripts/demo_data.py`), not against
other people's deployments.
