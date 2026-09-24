#!/usr/bin/env bash
#
# push-sandbox.sh -- push the current state of main to the topotrace-sandbox
# remote (public demo/showcase environment), never the other way around.
#
# The sandbox repo (topotracehq/topotrace-sandbox) is a SEPARATE remote,
# "sandboxrepo" in this checkout, deployed to independently of the primary
# repo's release process (see docs/RELEASING.md and cmd/topotrace's own
# release workflow for that). It exists so demo-only code -- most notably
# the visitor-metrics instrumentation kept on the local
# save/sandbox-visitor-metrics branch -- can ship to the public sandbox
# without ever landing in the real product's main branch or release
# artifacts. See "i do not want that in this branch, it is only for the
# sandbox" in the project history for why that separation is deliberate.
#
# What this script does:
#   1. Refuses to run with a dirty working tree or from anywhere but main.
#   2. Fetches and fast-forward-verifies against origin/main (never pushes
#      a main that hasn't actually been reviewed/merged through the normal
#      PR flow -- this script is a deploy step, not a merge step).
#   3. Runs the same verification gate as a normal release: gofmt, go vet,
#      go build, go test.
#   4. Pushes main to sandboxrepo's main branch, plus --tags if -t/--tags
#      is given.
#
# What it deliberately does NOT do: automatically layer the
# visitor-metrics-only commit (or any other sandbox-only patch) on top.
# That branch was cut a long time ago against a much older main and its
# raw diff no longer applies cleanly -- blindly replaying it here would
# silently reintroduce stale code or drop features main has gained since.
# If sandbox-only extras need to go out, reconcile them onto a fresh
# branch off current main by hand (file by file, e.g.
# `git show save/sandbox-visitor-metrics -- internal/api/sandbox.go`),
# verify with the same build/vet/test gate, and pass that branch with -b.
#
# Usage:
#   scripts/push-sandbox.sh                  # push main as-is
#   scripts/push-sandbox.sh --tags           # also push tags
#   scripts/push-sandbox.sh -b some-branch    # push a different local branch
#   scripts/push-sandbox.sh --dry-run        # verify + show what would push, don't push
#
# Requires: the topotrace_sandbox_deploy SSH key (deploy key on
# topotracehq/topotrace-sandbox) readable at ~/.ssh/topotrace_sandbox_deploy,
# and the "sandboxrepo" git remote already configured
# (git@github.com:topotracehq/topotrace-sandbox.git).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BRANCH="main"
PUSH_TAGS=false
DRY_RUN=false
SANDBOX_KEY="${TOPOTRACE_SANDBOX_DEPLOY_KEY:-$HOME/.ssh/topotrace_sandbox_deploy}"
REMOTE="sandboxrepo"

usage() {
  grep '^#' "$0" | sed -n '/^# Usage:/,/^# Requires:/p' | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -b|--branch) BRANCH="$2"; shift 2 ;;
    -t|--tags) PUSH_TAGS=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

if [ ! -f "$SANDBOX_KEY" ]; then
  echo "error: sandbox deploy key not found at $SANDBOX_KEY" >&2
  echo "  (set TOPOTRACE_SANDBOX_DEPLOY_KEY to point at it if it lives elsewhere)" >&2
  exit 1
fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "error: no '$REMOTE' git remote configured in this checkout" >&2
  echo "  expected: git remote add $REMOTE git@github.com:topotracehq/topotrace-sandbox.git" >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is not clean -- commit, stash, or discard changes first" >&2
  git status --short >&2
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" != "$BRANCH" ]; then
  echo "error: currently on '$CURRENT_BRANCH', not '$BRANCH' -- checkout $BRANCH first (or pass -b to push a different branch you're actually on)" >&2
  exit 1
fi

echo "==> Fetching origin"
git fetch origin "$BRANCH"

LOCAL_SHA="$(git rev-parse "$BRANCH")"
ORIGIN_SHA="$(git rev-parse "origin/$BRANCH")"
if [ "$LOCAL_SHA" != "$ORIGIN_SHA" ]; then
  echo "error: local $BRANCH ($LOCAL_SHA) does not match origin/$BRANCH ($ORIGIN_SHA)." >&2
  echo "  This script only ever deploys what has already gone through the normal PR flow on origin." >&2
  echo "  git pull --ff-only, or push your changes to origin first, then re-run." >&2
  exit 1
fi

echo "==> Verifying: gofmt"
FMT_OUT="$(gofmt -l $(find . -type f -name '*.go' -not -path './vendor/*'))"
if [ -n "$FMT_OUT" ]; then
  echo "error: the following files are not gofmt'd:" >&2
  echo "$FMT_OUT" >&2
  exit 1
fi

echo "==> Verifying: go vet"
go vet ./...

echo "==> Verifying: go build"
go build ./...

echo "==> Verifying: go test"
go test ./...

echo "==> All checks passed. Pushing $BRANCH ($LOCAL_SHA) to $REMOTE"

GIT_SSH_COMMAND="ssh -i $SANDBOX_KEY -o IdentitiesOnly=yes -o BatchMode=yes"
export GIT_SSH_COMMAND

if [ "$DRY_RUN" = true ]; then
  echo "==> --dry-run set: would run:"
  echo "    git push $REMOTE $BRANCH:main"
  [ "$PUSH_TAGS" = true ] && echo "    git push $REMOTE --tags"
  exit 0
fi

git push "$REMOTE" "$BRANCH:main"

if [ "$PUSH_TAGS" = true ]; then
  echo "==> Pushing tags"
  git push "$REMOTE" --tags
fi

echo "==> Done. https://github.com/topotracehq/topotrace-sandbox"
