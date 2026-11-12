#!/usr/bin/env bash
# The checks every pull request and every on-behalf release run before building.
#   bash on-behalf/release/preflight.sh          the versions agree; the fixture set is present; the copies match
#   bash on-behalf/release/preflight.sh 0.1.0    ...and they equal the tag's version, and the fixtures are final
# Exit 0 when every check holds, 1 when one fails, 2 when a check could not run.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
want=${1-}
failed=0
fail() { echo "preflight: $*" >&2; failed=1; }

js=$(node -p 'require("./js/package.json").version') || exit 2
lock=$(node -p 'require("./js/package-lock.json").version') || exit 2
[ -n "$js" ] || exit 2
[ "$lock" = "$js" ] ||
  fail "js/package-lock.json is $lock and js/package.json is $js; rerun npm install --package-lock-only"
[ -z "$want" ] || [ "$js" = "$want" ] || fail "the tag names $want and js/package.json is $js"

# The fixture set js/package.json names (varketa.fixtures, "v<n>") is present, its manifest names itself, and
# every case it lists exists. A release needs a final set: a provisional one is never published.
set_name=$(node -p 'const v = require("./js/package.json").varketa?.fixtures; /^v(0|[1-9][0-9]*)$/.test(v) ? v : ""') ||
  exit 2
if [ -z "$set_name" ]; then
  fail "js/package.json's varketa.fixtures is not v<n>"
elif [ ! -f "fixtures/$set_name/manifest.json" ]; then
  fail "js/package.json names fixtures $set_name, and there is no fixtures/$set_name/manifest.json"
else
  # shellcheck disable=SC2016 # the script is JavaScript; its ${...} are template literals
  node -e '
    const fs = require("fs");
    const [dir, name, release] = process.argv.slice(1);
    const m = JSON.parse(fs.readFileSync(`${dir}/manifest.json`, "utf8"));
    const bad = [];
    if (m.version !== name) bad.push(`its manifest names ${m.version}`);
    if (!Array.isArray(m.cases) || m.cases.length === 0) bad.push("it lists no case");
    for (const c of m.cases ?? []) if (!fs.existsSync(`${dir}/cases/${c}.json`)) bad.push(`case ${c} is missing`);
    if (release === "1" && m.provisional !== false) bad.push("it is provisional, and a release needs the final set");
    if (bad.length) { console.error(`preflight: fixtures ${name}: ${bad.join("; ")}`); process.exit(1); }
  ' "fixtures/$set_name" "$set_name" "$([ -n "$want" ] && echo 1 || echo 0)" || failed=1
fi

# The package ships only what is inside js/, so it carries copies of the root LICENSE and of on-behalf/README.md.
cmp -s ../LICENSE js/LICENSE ||
  fail "on-behalf/js/LICENSE is not the root LICENSE byte for byte; cp LICENSE on-behalf/js/"
cmp -s README.md js/README.md ||
  fail "on-behalf/js/README.md is not on-behalf/README.md byte for byte; cp on-behalf/README.md on-behalf/js/"

[ "$failed" = 0 ] && echo "preflight: OK, version $js, fixtures $set_name${want:+, as the tag names}"
exit "$failed"
