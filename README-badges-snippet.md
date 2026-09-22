Paste this near the top of README.md, right under the title, once the repo
is public and the workflows above have run at least once (badges show
"unknown" until then):

```markdown
[![CI](https://github.com/topotracehq/topotrace/actions/workflows/ci.yml/badge.svg)](https://github.com/topotracehq/topotrace/actions/workflows/ci.yml)
[![CodeQL](https://github.com/topotracehq/topotrace/actions/workflows/codeql.yml/badge.svg)](https://github.com/topotracehq/topotrace/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/topotracehq/topotrace)](https://goreportcard.com/report/github.com/topotracehq/topotrace)
[![License](https://img.shields.io/github/license/topotracehq/topotrace)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/topotracehq/topotrace)](https://github.com/topotracehq/topotrace/releases)
```

The CI badge covers build/test/gofmt/vet, govulncheck, gosec, and gitleaks
(all four jobs in `ci.yml`) — if any of them fail, the badge goes red. The
CodeQL badge is separate since it's a different workflow. Go Report Card is
free, no setup beyond the repo being public — it just needs a first visit to
https://goreportcard.com/report/github.com/topotracehq/topotrace to index it.

For a fuller writeup than a badge row, consider adding a short "Security &
Code Quality" section to the README body itself pointing at SECURITY.md and
naming what's scanned (dependency CVEs via govulncheck, static analysis via
gosec + CodeQL, committed secrets via gitleaks, on every push and PR).
