#!/usr/bin/env bash
# Plants package.json pairs against check-lockstep.sh. On the real tree that
# script only ever passes, so nothing else shows it can fail.
#
# Usage: check-lockstep.test.sh [path/to/check-lockstep.sh]
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=${1:-$here/check-lockstep.sh}
[ -f "$script" ] || { echo "no script at $script" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/check-lockstep.XXXXXX")
trap 'rm -rf "$work"' EXIT
fails=0

# run <name> <pass|fail> <ts version> <sdk version> <dependency spec>
run() {
  local name=$1 want=$2 t="$work/$1" got
  mkdir -p "$t/scripts" "$t/ts" "$t/sdk"
  cp "$script" "$t/scripts/check-lockstep.sh"
  chmod +x "$t/scripts/check-lockstep.sh"
  printf '{"name":"@txnlab/zs-proto","version":"%s"}\n' "$3" >"$t/ts/package.json"
  if [ "$5" = none ]; then
    printf '{"name":"@txnlab/zerosignal","version":"%s"}\n' "$4" >"$t/sdk/package.json"
  else
    printf '{"name":"@txnlab/zerosignal","version":"%s","dependencies":{"@txnlab/zs-proto":"%s"}}\n' "$4" "$5" >"$t/sdk/package.json"
  fi
  if "$t/scripts/check-lockstep.sh" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$want" ]; then
    printf 'ok       %-20s want=%s\n' "$name" "$want"
  else
    printf 'MISMATCH %-20s want=%s got=%s\n' "$name" "$want" "$got"
    fails=$((fails + 1))
  fi
}

run matching_pair     pass 1.2.3 1.2.3 'workspace:*'
run versions_differ   fail 1.2.3 1.2.4 'workspace:*'
run caret_workspace   fail 1.2.3 1.2.3 'workspace:^'
run literal_version   fail 1.2.3 1.2.3 '1.2.3'
run range_version     fail 1.2.3 1.2.3 '^1.2.3'
run missing_dependency fail 1.2.3 1.2.3 none

if [ "$fails" -gt 0 ]; then
  echo "$fails case(s) mismatched" >&2
  exit 1
fi
