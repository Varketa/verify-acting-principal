#!/usr/bin/env bash
# The release workflow's last check (RELEASING.md): what npm and PyPI now serve for VERSION is byte for byte what
# release/build.sh built into DIR. npm's dist.integrity must equal the tarball's sha512, and PyPI's files for the
# version must be exactly the wheel and sdist, each with the sha256 in DIR/SHA256SUMS.
#   bash release/read-back.sh DIR VERSION
# Registries can lag a publish by minutes, so each side is read up to READBACK_ATTEMPTS times (default 21), 30 s
# apart, about ten minutes, before it fails.
# Exit 0 when both match, 1 when either differs or never appears.
set -euo pipefail
[ $# = 2 ] || { echo "usage: read-back.sh DIR VERSION" >&2; exit 2; }
dir=$1 version=$2

python3 - "$dir" "$version" <<'PY'
import base64, hashlib, http.client, json, os, pathlib, subprocess, sys, time, urllib.request

dir, version = pathlib.Path(sys.argv[1]), sys.argv[2]
tgz = dir / "npm" / f"varketa-verify-acting-principal-{version}.tgz"
want_integrity = "sha512-" + base64.b64encode(hashlib.sha512(tgz.read_bytes()).digest()).decode()
want_pypi = {}
for line in (dir / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    if name.startswith("pypi/"):
        want_pypi[name.removeprefix("pypi/")] = digest
if len(want_pypi) != 2:
    sys.exit(f"read-back: SHA256SUMS names {sorted(want_pypi)}; want a wheel and an sdist")

def npm_integrity():
    r = subprocess.run(["npm", "view", f"@varketa/verify-acting-principal@{version}", "dist.integrity"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None

def pypi_files():
    url = f"https://pypi.org/pypi/varketa-verify-acting-principal/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)
    except (OSError, http.client.HTTPException, ValueError):  # URLError and TimeoutError are OSErrors
        return None
    return {f["filename"]: f["digests"]["sha256"] for f in data["urls"]}

attempts = int(os.environ.get("READBACK_ATTEMPTS", "21"))

def settle(name, read, want):
    got = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(30)
        got = read()
        if got == want:
            print(f"read-back: {name} OK")
            return True
    print(f"read-back: {name} serves {got!r}; want {want!r}", file=sys.stderr)
    return False

ok = settle("npm", npm_integrity, want_integrity)
ok = settle("PyPI", pypi_files, want_pypi) and ok
sys.exit(0 if ok else 1)
PY
