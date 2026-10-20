#!/usr/bin/env bash
# Build both packages into OUT and check what each one ships (RELEASING.md).
#   bash release/build.sh OUT
# OUT/npm holds the npm tarball, OUT/pypi the wheel and sdist, OUT/SHA256SUMS every artifact's digest.
# Needs node and npm, and python3 with `build` installed. Exit 0 when built and every check holds, 1 otherwise.
set -euo pipefail
[ $# = 1 ] || { echo "usage: build.sh OUT" >&2; exit 2; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$1/npm" "$1/pypi"
out=$(cd "$1" && pwd)
[ -z "$(ls -A "$out/npm")" ] && [ -z "$(ls -A "$out/pypi")" ] ||
  { echo "build: $out/npm and $out/pypi must start empty" >&2; exit 2; }
version=$(node -p "require('$root/js/package.json').version")

(cd "$root/js" && npm ci --ignore-scripts && npm run build && npm pack --ignore-scripts --pack-destination "$out/npm")
# pip, which build runs to fill its isolated environment, reads PIP_CONSTRAINT, so the backend is pinned too.
PIP_CONSTRAINT="$root/release/build-constraints.txt" python3 -m build --outdir "$out/pypi" "$root/python"

python3 - "$out" "$version" <<'PY'
import hashlib, pathlib, sys, tarfile, zipfile

out, version = pathlib.Path(sys.argv[1]), sys.argv[2]
failed = False
def fail(message):
    global failed
    print(f"build: {message}", file=sys.stderr)
    failed = True

def names(path):
    if path.suffix == ".whl":
        return set(zipfile.ZipFile(path).namelist())
    return set(tarfile.open(path).getnames())

# Exactly the artifacts this version names, and nothing else.
want = {
    "npm": {f"varketa-verify-acting-principal-{version}.tgz"},
    "pypi": {f"varketa_verify_acting_principal-{version}-py3-none-any.whl",
             f"varketa_verify_acting_principal-{version}.tar.gz"},
}
for sub, expected in want.items():
    got = {p.name for p in (out / sub).iterdir()}
    if got != expected:
        fail(f"{sub}/ holds {sorted(got)}; want {sorted(expected)}")
if failed:
    sys.exit(1)

tgz = out / "npm" / f"varketa-verify-acting-principal-{version}.tgz"
whl = out / "pypi" / f"varketa_verify_acting_principal-{version}-py3-none-any.whl"
sdist = out / "pypi" / f"varketa_verify_acting_principal-{version}.tar.gz"
for path, required in [
    (tgz, {"package/package.json", "package/LICENSE", "package/README.md", "package/dist/index.js",
           "package/dist/index.d.ts"}),
    (whl, {"varketa_verify_acting_principal/__init__.py",
           f"varketa_verify_acting_principal-{version}.dist-info/licenses/LICENSE"}),
    (sdist, {f"varketa_verify_acting_principal-{version}/LICENSE",
             f"varketa_verify_acting_principal-{version}/README.md",
             f"varketa_verify_acting_principal-{version}/src/varketa_verify_acting_principal/__init__.py"}),
]:
    missing = required - names(path)
    if missing:
        fail(f"{path.name} lacks {sorted(missing)}")
if failed:
    sys.exit(1)

lines = []
for path in (tgz, whl, sdist):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path.parent.name}/{path.name}\n")
(out / "SHA256SUMS").write_text("".join(lines))
print("build: OK\n" + "".join(lines), end="")
PY
