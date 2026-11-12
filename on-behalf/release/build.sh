#!/usr/bin/env bash
# Build the on-behalf npm package into OUT and check what it ships.
#   bash on-behalf/release/build.sh OUT
# OUT/npm holds the tarball, OUT/SHA256SUMS its digest. Needs node, npm and python3.
# Exit 0 when built and every check holds, 1 otherwise, 2 on a usage error.
set -euo pipefail
[ $# = 1 ] || { echo "usage: build.sh OUT" >&2; exit 2; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$1/npm"
out=$(cd "$1" && pwd)
[ -z "$(ls -A "$out/npm")" ] || { echo "build: $out/npm must start empty" >&2; exit 2; }
version=$(node -p "require('$root/js/package.json').version")

(cd "$root/js" && npm ci --ignore-scripts && npm run build && npm pack --ignore-scripts --pack-destination "$out/npm")

python3 - "$out" "$version" <<'PY'
import hashlib, pathlib, sys, tarfile

out, version = pathlib.Path(sys.argv[1]), sys.argv[2]
name = f"varketa-mcp-on-behalf-{version}.tgz"
got = {p.name for p in (out / "npm").iterdir()}
if got != {name}:
    sys.exit(f"build: npm/ holds {sorted(got)}; want {[name]}")
tgz = out / "npm" / name
names = set(tarfile.open(tgz).getnames())
required = {"package/package.json", "package/LICENSE", "package/README.md"}
for m in ("index", "clerk"):
    required |= {f"package/dist/{m}.js", f"package/dist/{m}.d.ts"}
missing = required - names
if missing:
    sys.exit(f"build: {name} lacks {sorted(missing)}")
# Only the built package: no sources, tests or fixtures.
stray = sorted(n for n in names if not (n.startswith("package/dist/") or n in required))
if stray:
    sys.exit(f"build: {name} ships {stray}")
line = f"{hashlib.sha256(tgz.read_bytes()).hexdigest()}  npm/{name}\n"
(out / "SHA256SUMS").write_text(line)
print("build: OK\n" + line, end="")
PY
