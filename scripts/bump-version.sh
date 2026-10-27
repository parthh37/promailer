#!/usr/bin/env bash
# Bumps the release version in Cargo.toml, Cargo.lock and CHANGELOG.md and prints the new version.
# Usage: scripts/bump-version.sh patch|minor|major
# Used by the Release workflow; also safe to run locally (review with `git diff`).
set -euo pipefail
cd "$(dirname "$0")/.."

# Prints the version that results from applying a bump of $kind (patch, minor or major)
# to $major.$minor.$patch. Rejects any other kind.
next_version() {
  local kind=$1 major=$2 minor=$3 patch=$4
  # TODO(parth): decide how each bump kind maps to the next version.
  echo "next_version is not implemented" >&2
  return 1
}

current=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
if [[ ! $current =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "Cargo.toml version '$current' is not X.Y.Z" >&2
  exit 1
fi
new=$(next_version "${1:-}" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")

# The GitHub release notes are the CHANGELOG section, so an empty one is a mistake, not a release.
if ! awk '/^## \[Unreleased\]/ { f = 1; next } /^## \[/ { f = 0 } f && NF { found = 1 } END { exit !found }' CHANGELOG.md; then
  echo "CHANGELOG.md has nothing under ## [Unreleased]; describe the changes before releasing" >&2
  exit 1
fi

rewrite() {
  local file=$1
  shift
  awk "$@" "$file" >"$file.tmp" && mv "$file.tmp" "$file"
}

# The first `version =` line is [workspace.package], which both crates inherit.
rewrite Cargo.toml -v v="$new" '!done && /^version = "/ { print "version = \"" v "\""; done = 1; next } 1'
# Only the two workspace crates; dependencies keep their versions, so `--locked` builds still pass.
rewrite Cargo.lock -v v="$new" '
  /^\[\[package\]\]/ { ours = 0 }
  /^name = "promailer(-manager)?"$/ { ours = 1 }
  ours && /^version = / { print "version = \"" v "\""; ours = 0; next }
  1'
# Unreleased entries become the new version's section; a fresh empty Unreleased stays on top.
rewrite CHANGELOG.md -v v="$new" -v d="$(date -u +%F)" '
  /^## \[Unreleased\]/ { print; print ""; print "## [" v "] - " d; next }
  1'

echo "$new"
