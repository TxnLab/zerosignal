#!/usr/bin/env bash
# Runs release.sh against a scratch repo and a bare "remote", with a fake gh. A
# pushed go/ tag can't be moved, so the guards that keep `tag` off the wrong commit
# are the ones pinned here; on the real repo they would only ever be met once.
#
# Usage: release.test.sh [path/to/release.sh]
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script=${1:-$here/release.sh}
[ -f "$script" ] || { echo "no script at $script" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/release-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
fails=0

mkdir -p "$work/bin"
printf '#!/bin/sh\nexit 0\n' >"$work/bin/gh"
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH" YES=1 REMOTE=origin
export GIT_AUTHOR_NAME=t GIT_COMMITTER_NAME=t
export GIT_AUTHOR_EMAIL=t@users.noreply.github.com GIT_COMMITTER_EMAIL=t@users.noreply.github.com

check() { # check <name> <pass|fail> <command...>
  local name=$1 want=$2 got
  shift 2
  if "$@" >"$work/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$want" ]; then
    printf 'ok       %-40s want=%s\n' "$name" "$want"
  else
    printf 'FAIL     %-40s want=%s got=%s\n' "$name" "$want" "$got"
    sed 's/^/         | /' "$work/out"
    fails=$((fails + 1))
  fi
}
expect() { # expect <name> <condition...>
  if "${@:2}"; then printf 'ok       %s\n' "$1"; else printf 'FAIL     %s\n' "$1"; fails=$((fails + 1)); fi
}

# A repo shaped like this one at 0.1.0, released as go/ts/sdk v0.1.0.
git init -q -b main "$work/seed"
cd "$work/seed" || exit 2
mkdir -p ts sdk scripts
printf '{\n    "name": "@txnlab/zs-proto",\n    "version": "0.1.0"\n}\n' >ts/package.json
printf '{\n    "name": "@txnlab/zerosignal",\n    "version": "0.1.0",\n    "dependencies": {"@txnlab/zs-proto": "workspace:*"}\n}\n' >sdk/package.json
printf '# log\n\n### a change (unreleased)\n\ntext (unreleased)\n\n### older (0.1.0)\n' >CHANGELOG.md
cp "$here/check-lockstep.sh" scripts/
cp "$script" scripts/release.sh
git add -A && git commit -qm "ts, sdk: 0.1.0"
git tag go/v0.1.0 && git tag ts/v0.1.0 && git tag sdk/v0.1.0
git clone -q --bare "$work/seed" "$work/remote.git"
git clone -q "$work/remote.git" "$work/repo"
cd "$work/repo" || exit 2
rel=./scripts/release.sh
merge() { git -C "$work/remote.git" update-ref refs/heads/main "refs/heads/$1"; }
remote_tag() { git -C "$work/remote.git" rev-parse --verify --quiet "refs/tags/$1^{commit}"; }
later_commit() { # adds a commit on the remote's main, as another merged PR would
  git -C "$work/seed" fetch -q "$work/remote.git" main && git -C "$work/seed" reset -q --hard FETCH_HEAD
  echo "$1" >>"$work/seed/notes" && git -C "$work/seed" add notes && git -C "$work/seed" commit -qm "$1"
  git -C "$work/seed" push -q "$work/remote.git" HEAD:main
}

check "prepare refuses a version not above main" fail $rel prepare 0.1.0
check "prepare refuses a lower version" fail $rel prepare 0.0.9
check "prepare refuses a leading zero" fail $rel prepare 0.02.0
check "prepare 0.2.0" pass $rel prepare 0.2.0
expect "both package.json files say 0.2.0" grep -q '"version": "0.2.0"' ts/package.json
expect "sdk/package.json says 0.2.0" grep -q '"version": "0.2.0"' sdk/package.json
expect "the ### heading is relabelled" grep -q '^### a change (0.2.0)$' CHANGELOG.md
expect "prose saying (unreleased) is left alone" grep -q '^text (unreleased)$' CHANGELOG.md
expect "the branch is on the remote" test -n "$(git -C "$work/remote.git" rev-parse --verify --quiet refs/heads/release/v0.2.0)"
check "prepare refuses a branch that exists" fail $rel prepare 0.2.0

check "tag before the merge pushes nothing" pass $rel tag
expect "no 0.2.0 tag before the merge" test -z "$(remote_tag go/v0.2.0)"

merge release/v0.2.0
version_commit=$(git -C "$work/remote.git" rev-parse main)
later_commit "a PR merged after the release PR"
check "tag after a later merge" pass $rel tag
for t in go/v0.2.0 ts/v0.2.0 sdk/v0.2.0; do
  expect "$t is on the version commit, not main's tip" test "$(remote_tag $t)" = "$version_commit"
done
check "tag again is a no-op" pass $rel tag

# An annotated tag at the right commit counts as present: ls-remote names the tag
# object unless asked for its peeled ^{} line.
git -C "$work/remote.git" tag -d ts/v0.2.0 >/dev/null
git -C "$work/remote.git" tag -a -m note ts/v0.2.0 "$version_commit"
git tag -d ts/v0.2.0 >/dev/null
check "an annotated tag at the right commit" pass $rel tag

# A tag already on another commit stops everything.
check "prepare 0.3.0" pass $rel prepare 0.3.0
merge release/v0.3.0
git -C "$work/remote.git" tag go/v0.3.0 "$version_commit"
check "tag refuses a go tag on another commit" fail $rel tag
expect "and pushes nothing" test -z "$(remote_tag ts/v0.3.0)"

if [ "$fails" -gt 0 ]; then echo "release.test.sh: $fails failed" >&2; exit 1; fi
