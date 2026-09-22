# Contributing to TopoTrace

Thanks for your interest in TopoTrace. This is a young project and we're glad
to have outside eyes on it, whether that's a bug report, a doc fix, or a new
feature.

## Ways to Contribute

- **Bug reports and feature requests**: open a GitHub Issue. For bugs,
  include your OS/platform, TopoTrace version (`topotrace -version`), and
  steps to reproduce.
- **Documentation**: fixes to `docs/*.md` or the README are always welcome,
  no issue needed first for small fixes.
- **Code**: bug fixes and small, well-scoped features can go straight to a
  PR. For anything larger (a new subsystem, a new plugin, a breaking change
  to the agent wire protocol), please open an issue first to discuss the
  approach before investing the time.
- **Plugins**: see [`docs/plugins.md`](docs/plugins.md) for the plugin
  protocol. Community plugins don't need to live in this repo — feel free to
  open a PR adding yours to a plugin directory/list once that exists, or
  just share it in Discussions.

## Development Setup

```bash
git clone https://github.com/topotracehq/topotrace.git
cd topotrace
go build ./cmd/topotrace
```

Requires Go 1.22+ and PostgreSQL for the server. See
[`deploy/systemd/README.md`](deploy/systemd/README.md) for a full local/dev
setup, and [`docs/`](docs/) for architecture and subsystem docs.

Run the test suite:

```bash
go test ./...
```

## Before Opening a PR

- Run `go vet ./...` and `gofmt -l .` — CI will fail on unformatted code.
- Add or update tests for behavior changes.
- Keep PRs focused — one logical change per PR is much easier to review
  than a bundle of unrelated fixes.
- If your change touches the agent-to-server wire protocol
  (`internal/ingest`), flag that explicitly in the PR description — it
  affects every platform's agent and needs extra care.

## Code Style

Standard Go conventions (`gofmt`, effective Go). No unusual formatting
requirements beyond that. Keep exported functions documented with a comment
starting with the function name, per Go convention.

## Security Issues

Please don't file security vulnerabilities as public issues — see
[SECURITY.md](SECURITY.md) for how to report them privately.

## License

By contributing, you agree that your contributions will be licensed under
the project's [Apache 2.0 License](LICENSE).
