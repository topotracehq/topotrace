# Security Policy

## Supported Versions

TopoTrace is currently pre-1.0. Security fixes are applied to the latest
released version on the `main` branch. There is no long-term support for
older tags at this time.

| Version | Supported |
| ------- | --------- |
| latest  | ✅ |
| older   | ❌ |

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Instead, report it privately using one of these methods:

1. **GitHub Private Vulnerability Reporting** (preferred): go to the
   [Security tab](https://github.com/topotracehq/topotrace/security) of this
   repository and click "Report a vulnerability." This opens a private
   discussion visible only to the maintainers.
2. **Email**: send details to **security@topotrace.org**.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof-of-concept if available
- The affected version/commit
- Any suggested remediation, if you have one

## What to Expect

- We aim to acknowledge new reports within **3 business days**.
- We'll work with you to understand and validate the issue, and keep you
  updated as a fix is developed.
- We ask that you give us a reasonable period to address the issue before
  any public disclosure. We're happy to credit reporters in release notes
  unless you'd prefer to stay anonymous.

## Scope

This policy covers the TopoTrace server, agents, plugins, and Helm chart in
this repository. Third-party dependencies should be reported to their own
maintainers, though we're glad to help coordinate if a dependency issue
affects TopoTrace directly.

## Automated Scanning

This repository is scanned on every push and pull request for known-vulnerable
dependencies, hardcoded secrets, and common Go security issues. See the
badges in the [README](README.md) for current status and
[`.github/workflows/`](.github/workflows/) for what runs.
