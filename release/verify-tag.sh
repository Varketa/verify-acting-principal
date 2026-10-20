#!/usr/bin/env bash
# The release workflow's first check (RELEASING.md): TAG is vX.Y.Z, annotated, signed with a signature GitHub
# verifies, and points at the checked-out commit, which is on main. Prints version=X.Y.Z to $GITHUB_OUTPUT.
# Reads TAG, GITHUB_REPOSITORY, GITHUB_OUTPUT and GH_TOKEN. Exit 0 when every check holds, 1 otherwise.
set -euo pipefail
: "${TAG:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_OUTPUT:?}"
fail() { echo "verify-tag: $*" >&2; exit 1; }

[[ $TAG =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail "$TAG is not vX.Y.Z"
ref=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG")
[ "$(jq -r .object.type <<<"$ref")" = tag ] || fail "$TAG is a lightweight tag; a release tag is annotated and signed (git tag -s)"
tag=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$(jq -r .object.sha <<<"$ref")")
[ "$(jq -r .verification.verified <<<"$tag")" = true ] ||
  fail "$TAG's signature is not verified by GitHub ($(jq -r .verification.reason <<<"$tag")); the signer's key belongs on their GitHub account"
target=$(jq -r .object.sha <<<"$tag")
[ "$(jq -r .object.type <<<"$tag")" = commit ] || fail "$TAG does not point at a commit"
[ "$target" = "$(git rev-parse HEAD)" ] || fail "$TAG points at $target, but the checkout is $(git rev-parse HEAD)"
git fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main
git merge-base --is-ancestor "$target" refs/remotes/origin/main || fail "$TAG's commit $target is not on main"

echo "version=${TAG#v}" >> "$GITHUB_OUTPUT"
echo "verify-tag: OK, $TAG at $target, signed and on main"
