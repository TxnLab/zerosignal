#!/usr/bin/env bash
# Plants inputs against check-no-hayai.sh. On the real tree that script only
# ever passes, so nothing else exercises the matching that makes it fail.
#
# Each case builds a throwaway tree (go/, ts/src, ts/test) holding the lines
# the real allow-list admits, plants one input, copies the script in (it cds
# to its own parent), runs it and compares pass/fail with the expectation.
#
# Usage: check-no-hayai.test.sh [path/to/check-no-hayai.sh]
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=${1:-$here/check-no-hayai.sh}
[ -f "$script" ] || { echo "no script at $script" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/check-no-hayai.XXXXXX")
cleanup() { chmod -R u+rwx "$work" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

fails=0

# The allow-listed lines, as the repository holds them.
seed() {
  local t=$1
  mkdir -p "$t/scripts" "$t/go/wire" "$t/go/cmd/releasenotes" "$t/ts/src" "$t/ts/test"
  cp "$script" "$t/scripts/check-no-hayai.sh"
  chmod +x "$t/scripts/check-no-hayai.sh"
  printf '%s\n' 'package wire' \
    '		{"prior major (6.0) — dropped at the 7.0 hayai→zs transport-label rename", "6.0", false},' \
    > "$t/go/wire/version_test.go"
  printf '%s\n' \
    "        ['prior major (6.0) — dropped at the 7.0 hayai→zs transport-label rename', '6.0', false]," \
    > "$t/ts/test/version.test.ts"
  printf '%s\n' 'package main' \
    '	// The private repo'"'"'s own name ("hayai-proxy" / "hayai-node"); the public' \
    > "$t/go/cmd/releasenotes/main.go"
  printf '%s\n' 'package main' \
    '		"hayai-node":                  true,' \
    '		"- Cloned from hayai-node.\n"' \
    > "$t/go/cmd/releasenotes/main_test.go"
  printf '%s\n' 'export const x = 1;' > "$t/ts/src/index.ts"
}

# run <name> <pass|fail> <plant-function>
run() {
  local name=$1 want=$2 plant=$3 t got
  t="$work/$name"
  seed "$t"
  "$plant" "$t"
  if "$t/scripts/check-no-hayai.sh" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$want" ]; then
    printf 'ok       %-26s want=%s\n' "$name" "$want"
  else
    printf 'MISMATCH %-26s want=%s got=%s\n' "$name" "$want" "$got"
    fails=$((fails + 1))
  fi
}

# Adds one allow-list pair to the copied script.
allow() {
  awk -v p="$2" -v x="$3" '{print} /^allowed=\(/{print "  '\''" p "'\'' '\''" x "'\''"}' \
    "$1/scripts/check-no-hayai.sh" > "$1/scripts/edited" &&
    mv "$1/scripts/edited" "$1/scripts/check-no-hayai.sh" &&
    chmod +x "$1/scripts/check-no-hayai.sh"
}

none()               { :; }
lower_in_go()        { printf '// hayai\n' > "$1/go/x.go"; }
upper_in_ts_src()    { printf '// HAYAI\n' > "$1/ts/src/x.ts"; }
in_ts_test()         { printf '// Hayai\n' > "$1/ts/test/x.test.ts"; }
invalid_utf8()       { printf '// \377 hayai\n' > "$1/go/x.txt"; }
name_only()          { printf 'package x\n' > "$1/go/hayai_util.go"; }
name_mixed_case()    { printf 'x\n' > "$1/ts/src/HayAI.ts"; }
name_with_space()    { printf 'x\n' > "$1/go/my hayai.txt"; }
empty_dir()          { mkdir "$1/ts/src/hayai"; }
new_line_in_allowed(){ printf '// hayai again\n' >> "$1/go/wire/version_test.go"; }
phrase_other_file()  { printf '// hayai→zs transport-label rename\n' > "$1/go/wire/other_test.go"; }
path_in_text()       { printf '// go/wire/version_test.go:1: hayai→zs transport-label rename\n' > "$1/go/y.go"; }
dot_wildcard_path()  { printf '// hayai→zs transport-label rename\n' > "$1/go/wire/version_test_go"; }
allowed_repo_name()  { printf '// hayai-node\n' >> "$1/go/cmd/releasenotes/main.go"; }
other_repo_name()    { printf '// hayai-client\n' >> "$1/go/cmd/releasenotes/main.go"; }
upper_repo_name()    { printf '// HAYAI-NODE\n' >> "$1/go/cmd/releasenotes/main_test.go"; }
# A second mention riding on an allowed line.
ride_repo_line()     { printf '	hayaiClient := "hayai-node"\n' >> "$1/go/cmd/releasenotes/main.go"; }
ride_rename_line()   { printf '// HayaiThing; hayai→zs transport-label rename\n' >> "$1/go/wire/version_test.go"; }
unreadable_file()    { printf 'x\n' > "$1/go/locked.txt"; chmod 000 "$1/go/locked.txt"; }
missing_dir()        { rm -rf "$1/ts/test"; }
# A malformed entry must fail the check, not filter every hit away.
bad_path_regex()     { allow "$1" 'go/x(\.go' 'hayai'; printf '// hayai\n' > "$1/go/x.go"; }
bad_text_regex()     { allow "$1" 'go/x\.go' 'hay(ai'; printf '// hayai\n' > "$1/go/x.go"; }
# The path regex is anchored at both ends.
path_suffix()        { printf '// hayai→zs transport-label rename\n' > "$1/go/wire/version_test.go.orig"; }
path_prefix()        { mkdir -p "$1/go/x/go/wire"; printf '// hayai→zs transport-label rename\n' > "$1/go/x/go/wire/version_test.go"; }
# Each entry admits its text in its own files only. The names differ from the
# allowed ones by a dot alone, so an unescaped dot or a widened directory
# pattern admits them.
ts_phrase_other()    { printf '// hayai→zs transport-label rename\n' > "$1/ts/test/version-test.ts"; }
repo_name_other()    { printf '// hayai-node\n' > "$1/go/cmd/releasenotes/main_go"; }
# Path matching stays case-sensitive after an earlier hit turned nocasematch on.
# ts/test is searched after go/, which always holds a hit, so this is never the
# first one.
path_case()          { printf '// hayai→zs transport-label rename\n' > "$1/ts/test/Version.test.ts"; }
# A backslash reaches the allow-list text as written, not unescaped by read.
backslash_repo_name(){ printf '%s\n' '// hayai\-node' >> "$1/go/cmd/releasenotes/main.go"; }
# A file name holding colons must not pose as an allow-listed path.
colon_in_path()      { mkdir -p "$1/go/wire/version_test.go:1:"; printf '// hayai→zs transport-label rename\n' > "$1/go/wire/version_test.go:1:/x.go"; }

# No mention anywhere: grep's no-match exit is the passing case.
empty_tree()         { : > "$1/go/wire/version_test.go"; : > "$1/ts/test/version.test.ts"
                       : > "$1/go/cmd/releasenotes/main.go"; : > "$1/go/cmd/releasenotes/main_test.go"; }
# The listed path is read back byte for byte. Each name below, read any other
# way, becomes an allowed path, and the planted mention is never searched.
newline_in_path()    { local d="$1/go/wire/version_test.go
go/wire"; mkdir -p "$d"; printf '// hayai\n' > "$d/version_test.go"; }
backslash_in_path()  { printf '// hayai\n' > "$1/go/wire/version_test.g\\o"; }
space_after_path()   { printf '// hayai\n' > "$1/go/wire/version_test.go "; }
tab_after_path()     { printf '// hayai\n' > "$1/go/wire/version_test.go	"; }

# run_reports <name> <text> <plant>: the failure must name <text> on stderr.
run_reports() {
  local name=$1 want=$2 plant=$3 t err
  t="$work/$name"
  seed "$t"
  "$plant" "$t"
  err=$("$t/scripts/check-no-hayai.sh" 2>&1 >/dev/null) && err=
  if [[ $err == *"$want"* ]]; then
    printf 'ok       %-26s\n' "$name"
  else
    printf 'MISMATCH %-26s stderr lacks %s\n' "$name" "$want"
    fails=$((fails + 1))
  fi
}

run baseline             pass none
run lower_in_go          fail lower_in_go
run upper_in_ts_src      fail upper_in_ts_src
run in_ts_test           fail in_ts_test
run invalid_utf8         fail invalid_utf8
run name_only            fail name_only
run name_mixed_case      fail name_mixed_case
run name_with_space      fail name_with_space
run empty_dir            fail empty_dir
run new_line_in_allowed  fail new_line_in_allowed
run phrase_other_file    fail phrase_other_file
run path_in_text         fail path_in_text
run dot_wildcard_path    fail dot_wildcard_path
run allowed_repo_name    pass allowed_repo_name
run other_repo_name      fail other_repo_name
run upper_repo_name      fail upper_repo_name
run ride_repo_line       fail ride_repo_line
run ride_rename_line     fail ride_rename_line
# root reads a mode-000 file, so the case has nothing to show there.
[ "$(id -u)" -eq 0 ] || run unreadable_file fail unreadable_file
run missing_dir          fail missing_dir
run bad_path_regex       fail bad_path_regex
run bad_text_regex       fail bad_text_regex
run path_suffix          fail path_suffix
run path_prefix          fail path_prefix
run ts_phrase_other      fail ts_phrase_other
run repo_name_other      fail repo_name_other
# On a case-insensitive file system Version.test.ts is the allowed file itself.
touch "$work/CaseProbe"
[ -e "$work/caseprobe" ] || run path_case fail path_case
run backslash_repo_name  fail backslash_repo_name
run colon_in_path        fail colon_in_path
run empty_tree           pass empty_tree
run newline_in_path      fail newline_in_path
run backslash_in_path    fail backslash_in_path
run space_after_path     fail space_after_path
run tab_after_path       fail tab_after_path

# The guard's listing file is removed whatever the verdict.
t="$work/tmp_cleaned"
seed "$t"
lower_in_go "$t"
mkdir "$work/tmpdir"
TMPDIR="$work/tmpdir" "$t/scripts/check-no-hayai.sh" >/dev/null 2>&1
if [ -z "$(ls -A "$work/tmpdir")" ]; then
  printf 'ok       %-26s\n' tmp_cleaned
else
  printf 'MISMATCH %-26s left %s\n' tmp_cleaned "$(ls -A "$work/tmpdir")"
  fails=$((fails + 1))
fi

run_reports reports_hit  'go/x.go:1:// hayai'  lower_in_go
run_reports reports_name 'go/hayai_util.go'    name_only

# The target CI runs (`make test`, also run by release.yml) must invoke the
# script. Dry run only, so no suite executes.
repo=$(cd "$(dirname "$script")/.." && pwd)
if [ -f "$repo/Makefile" ]; then
  # Captured first: `make | grep -q` under pipefail fails on make's SIGPIPE.
  dry=$(make -n -C "$repo" test 2>/dev/null || true)
  if printf '%s\n' "$dry" | grep 'check-no-hayai\.sh' >/dev/null; then
    printf 'ok       %-26s\n' make_test_runs_guard
  else
    printf 'MISMATCH %-26s make test does not run the guard\n' make_test_runs_guard
    fails=$((fails + 1))
  fi
  # check-no-hayai must run this test too, or the cases above retire silently.
  dry=$(make -n -C "$repo" check-no-hayai 2>/dev/null || true)
  if printf '%s\n' "$dry" | grep 'check-no-hayai\.test\.sh' >/dev/null; then
    printf 'ok       %-26s\n' make_target_runs_test
  else
    printf 'MISMATCH %-26s make check-no-hayai does not run the test\n' make_target_runs_test
    fails=$((fails + 1))
  fi
  # And a guard failure must fail the target (no `-` prefix, no `|| true`). The
  # test is stubbed in the copy so the target does not recurse into it.
  t="$work/make_propagates"
  seed "$t"
  lower_in_go "$t"
  cp "$repo/Makefile" "$t/Makefile"
  printf '#!/bin/sh\n' > "$t/scripts/check-no-hayai.test.sh"
  chmod +x "$t/scripts/check-no-hayai.test.sh"
  make -s -C "$t" check-no-hayai >/dev/null 2>&1
  rc=$?
  # 127 is make missing, which proves nothing either way.
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 127 ]; then
    printf 'MISMATCH %-26s make check-no-hayai passed a failing guard\n' make_propagates
    fails=$((fails + 1))
  else
    printf 'ok       %-26s\n' make_propagates
  fi
  # A failing test must fail the target too, with the guard itself clean.
  t="$work/make_propagates_test"
  seed "$t"
  cp "$repo/Makefile" "$t/Makefile"
  printf '#!/bin/sh\nexit 1\n' > "$t/scripts/check-no-hayai.test.sh"
  chmod +x "$t/scripts/check-no-hayai.test.sh"
  make -s -C "$t" check-no-hayai >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 127 ]; then
    printf 'MISMATCH %-26s make check-no-hayai passed a failing test\n' make_propagates_test
    fails=$((fails + 1))
  else
    printf 'ok       %-26s\n' make_propagates_test
  fi
fi

[ "$fails" -eq 0 ] || { echo "$fails case(s) disagree" >&2; exit 1; }
