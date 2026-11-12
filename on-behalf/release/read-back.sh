#!/usr/bin/env bash
# The on-behalf release's last check: what npm serves for VERSION is byte for byte what build.sh built into DIR.
# npm's dist.integrity must equal the tarball's sha512.
#   bash on-behalf/release/read-back.sh DIR VERSION
# npm can lag a publish by minutes, so it is read up to READBACK_ATTEMPTS times (default 21), 30 s apart.
# Exit 0 when it matches, 1 when it differs or never appears, 2 on a usage error.
set -euo pipefail
[ $# = 2 ] || { echo "usage: read-back.sh DIR VERSION" >&2; exit 2; }
dir=$1 version=$2
tgz="$dir/npm/varketa-mcp-on-behalf-$version.tgz"
[ -f "$tgz" ] || { echo "read-back: no $tgz" >&2; exit 2; }
want="sha512-$(openssl dgst -sha512 -binary "$tgz" | openssl base64 -A)"
attempts=${READBACK_ATTEMPTS:-21}
got=
for ((i = 0; i < attempts; i++)); do
  [ "$i" = 0 ] || sleep 30
  got=$(npm view "@varketa/mcp-on-behalf@$version" dist.integrity 2>/dev/null) || got=
  if [ "$got" = "$want" ]; then
    echo "read-back: npm OK"
    exit 0
  fi
done
echo "read-back: npm serves '$got'; want '$want'" >&2
exit 1
