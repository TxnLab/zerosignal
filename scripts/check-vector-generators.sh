#!/usr/bin/env bash
# Fails when a golden-vector generator has no matching line in the Makefile.
#
# Each generator registers its -update flag in its own package, so no single
# `go test ./... -update` regenerates them all and the Makefile has to list
# (package, test, flag) triples by hand. That list once silently dropped three
# generators, leaving their fixtures stale while `make update-vectors` exited 0.
#
# A generator is any Test*Vectors func in a package whose tests declare a
# flag.Bool. Its flag is the one declared in its own file, else the package's
# shared -update — and the flag is checked too, because invoking the wrong
# defined flag regenerates nothing without failing. Only tab-indented recipe
# lines count, so commenting a line out is caught the same as deleting it.
set -euo pipefail
cd "$(dirname "$0")/.."

tab=$(printf '\t')
missing=0
for file in $(grep -rlE --include='*_test.go' '^func Test[A-Za-z0-9_]*Vectors\(' go); do
  dir=$(dirname "$file")
  grep -qE '^[^/]*flag\.Bool\(' "$dir"/*_test.go || continue

  flagname=$(sed -nE 's/^[^/]*flag\.Bool\("([^"]+)".*/\1/p' "$file" | head -n 1)
  flagname=${flagname:-update}
  pkg="./${dir#go/}"

  for name in $(sed -nE 's/^func (Test[A-Za-z0-9_]*Vectors)\(.*/\1/p' "$file"); do
    if ! grep -qE "^${tab}[^#]*test +${pkg//./\\.} +-run +${name} +-${flagname}( |$)" Makefile; then
      echo "Makefile has no generator line for: go test $pkg -run $name -$flagname" >&2
      missing=1
    fi
  done
done

exit "$missing"
