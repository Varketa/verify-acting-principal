#!/usr/bin/env bash
# The checks every pull request and every release run before building (RELEASING.md).
#   bash release/preflight.sh            versions agree with each other; the package copies match the root
#   bash release/preflight.sh 0.2.1      ...and they equal the version the tag names
#   and either way, the claim set the release names is one the libraries accept, with its vectors present
# Exit 0 when every check holds, 1 when one fails, 2 when a check could not run.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
want=${1-}
failed=0
fail() { echo "preflight: $*" >&2; failed=1; }

js=$(node -p 'require("./js/package.json").version') || exit 2
lock=$(node -p 'require("./js/package-lock.json").version') || exit 2
py=$(python3 -c 'import sys, tomllib; print(tomllib.load(open("python/pyproject.toml", "rb"))["project"]["version"])') || exit 2
[ -n "$js" ] && [ -n "$py" ] || exit 2

[ "$js" = "$py" ] || fail "js/package.json is $js and python/pyproject.toml is $py; a release carries one version"
[ "$lock" = "$js" ] || fail "js/package-lock.json is $lock and js/package.json is $js; rerun npm install --package-lock-only"
if [ -n "$want" ]; then
  [ "$js" = "$want" ] || fail "the tag names $want and js/package.json is $js"
  [ "$py" = "$want" ] || fail "the tag names $want and python/pyproject.toml is $py"
fi

# The claim set this release is for: the vector set js/package.json names (varketa.vectors, "v<ver>") is one of the
# claim-set versions it says the libraries accept (varketa.claimSetVersions), and that set is in vectors/. The tests
# hold both libraries' accepted versions to the vector sets.
ver=$(node -p 'const v = require("./js/package.json").varketa.vectors; /^v[1-9][0-9]*$/.test(v) ? v.slice(1) : ""') || exit 2
if [ -z "$ver" ]; then
  fail "js/package.json's varketa.vectors is not v<ver>"
else
  node -e 'process.exit(require("./js/package.json").varketa.claimSetVersions.includes(Number(process.argv[1])) ? 0 : 1)' "$ver" ||
    fail "js/package.json names vectors v$ver, but its claimSetVersions does not include $ver"
  [ -d "vectors/v$ver" ] || fail "js/package.json names vectors v$ver, and there is no vectors/v$ver"
fi

# A package ships only what is inside its own directory, so each carries a copy of the license and the README;
# the copies are the root's byte for byte.
for f in LICENSE README.md; do
  for d in js python; do
    cmp -s "$f" "$d/$f" || fail "$d/$f is not the root $f byte for byte; copy it: cp $f $d/$f"
  done
done

[ "$failed" = 0 ] && echo "preflight: OK, version $js${want:+, as the tag names}"
exit "$failed"
