# Security Policy

Blockwart stores operational knowledge and credential references. A security
report may itself reveal sensitive infrastructure or authentication details,
so do not open a public issue for a vulnerability.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow from the repository's
**Security** tab. Include the affected version or commit, impact, minimal
reproduction steps, and any proposed mitigation. Do not include live
credentials, production catalog exports, or unrelated personal data.

If private vulnerability reporting is temporarily unavailable, open a public
issue that asks the maintainer to establish a private reporting channel. Do
not include vulnerability details in that issue.

## Supported versions

Security fixes target the current `main` branch. Older tags and published
releases do not have a separate backport or maintenance guarantee. A release
version alone does not establish that it includes later security fixes; check
the relevant advisory and fixed commit. Deployment operators remain responsible
for protecting their
catalog database, credentials, reverse proxy, backups, and runtime secrets.

The product's technical security model is documented in
[`docs/security.md`](docs/security.md).
