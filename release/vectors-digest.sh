#!/usr/bin/env bash
# The digest of one vector set, for the release notes (RELEASING.md): sha256 over the set's manifest, one
# "<sha256 of the file>  <path from the repository root>\n" line per file, sorted by path bytes.
#   bash release/vectors-digest.sh v4      prints sha256:<hex>
# Exit 0 when the set exists and holds a file, 1 when it does not, 2 when the name is not v<ver>.
set -euo pipefail
[ $# = 1 ] && [[ $1 =~ ^v[1-9][0-9]*$ ]] || { echo "usage: vectors-digest.sh v<ver>" >&2; exit 2; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python3 - "$root" "$1" <<'PY'
import hashlib, pathlib, sys

root, name = pathlib.Path(sys.argv[1]), sys.argv[2]
base = root / "vectors" / name
files = sorted((p for p in base.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root).as_posix().encode())
if not files:
    sys.exit(f"vectors-digest: vectors/{name} holds no file")
manifest = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n" for p in files)
print("sha256:" + hashlib.sha256(manifest.encode()).hexdigest())
PY
