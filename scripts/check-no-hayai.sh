#!/usr/bin/env bash
# Fails when the old project name, hayai, appears in the published code or its
# tests, in a file's contents or its name.
#
# The protocol is ZeroSignal (`zs`) everywhere a caller can see it, and the
# names that came in with the extraction from the proxy were renamed before
# the zs package's first tag. This keeps them from creeping back through
# copied code or comments.
#
# The allow-list is pairs of a file and the text that file may hold. The text
# is removed from that file's matching lines and whatever is left is checked
# again, so a second mention riding on an allowed line still fails. Its entries
# are history and real repository names, not protocol names.
#
# scripts/check-no-hayai.test.sh plants inputs against this script; run it
# after changing the matching.
set -euo pipefail
cd "$(dirname "$0")/.."
# Bytes, not characters: in a UTF-8 locale GNU grep -I skips a file with an
# invalid sequence as binary, and the mention in it with it.
export LC_ALL=C

# Path regex (whole path), then the text regex allowed in it. Case-sensitive,
# so HAYAI-NODE is not the repository's name.
allowed=(
  # The test case for the 7.0 rename, which names what was renamed.
  'go/wire/version_test\.go'                'hayai→zs transport-label rename'
  'ts/test/version\.test\.ts'               'hayai→zs transport-label rename'
  # The private repositories' real names, which release notes rewrite.
  'go/cmd/releasenotes/main(_test)?\.go'    'hayai-(node|proxy)'
)

# The files are listed NUL-separated and each is searched on its own, so a
# path is never cut out of grep's path:line:text, where a file named
# `go/wire/version_test.go:1:/x.go` would read as the allowed one.
#
# grep exits 1 for "no match", which is the passing case; any other non-zero
# (a missing directory, an unreadable file) must fail the check rather than
# read as an empty result. The listing goes through a file, not a process
# substitution, because only a plain command keeps that exit status.
# A template, because macOS mktemp without one ignores TMPDIR.
files=$(mktemp "${TMPDIR:-/tmp}/check-no-hayai.XXXXXX")
trap 'rm -f "$files"' EXIT
grep -rlIi --null hayai go ts/src ts/test >"$files" || [ $? -eq 1 ]
bad=()
while IFS= read -r -d '' path; do
  lines=$(grep -nIi hayai "$path")
  while IFS= read -r hit; do
    text=${hit#*:}
    for ((i = 0; i < ${#allowed[@]}; i += 2)); do
      # A malformed path regex matches nothing, which leaves the hit standing;
      # a malformed text regex fails sed and, through set -e, the check.
      if [[ $path =~ ^(${allowed[i]})$ ]]; then
        text=$(printf '%s\n' "$text" | sed -E "s/${allowed[i + 1]}//g")
      fi
    done
    # A test, not a pipe into grep -q: grep quitting on the match can SIGPIPE
    # printf, and pipefail would then read the hit as clean.
    shopt -s nocasematch
    if [[ $text == *hayai* ]]; then
      bad+=("$path:$hit")
    fi
    shopt -u nocasematch
  done <<<"$lines"
done <"$files"
names=$(find go ts/src ts/test -iname '*hayai*')

if [ ${#bad[@]} -gt 0 ] || [ -n "$names" ]; then
  echo "the old project name appears under go/ or ts/ (rename it, or extend the allow-list in $0):" >&2
  { printf '%s\n' "$names"; [ ${#bad[@]} -eq 0 ] || printf '%s\n' "${bad[@]}"; } | sed '/^$/d' >&2
  exit 1
fi
