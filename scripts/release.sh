#!/usr/bin/env bash
# Cuts a lockstep release of the Go module, @txnlab/zs-proto and @txnlab/zerosignal
# (README "Releasing"). Three steps, each one command:
#
#   release.sh prepare X.Y.Z   Branch release/vX.Y.Z off the remote's main, set both
#                              package.json versions, relabel the CHANGELOG's
#                              "(unreleased)" headings, commit, push, open the PR.
#   release.sh tag             After that PR merges: tag the commit on main that set
#                              the version go/ ts/ sdk/ vX.Y.Z and push exactly those.
#   release.sh status [X.Y.Z]  What is live: the tags, the release.yml runs, npm and
#                              the Go module.
#
# REMOTE names the TxnLab/zerosignal remote (default origin). Set YES=1 to skip the
# confirmation before tags are pushed. scripts/release.test.sh exercises all three
# against a scratch remote.
#
# `tag` takes no version: it reads it from main's package.json files and tags the
# commit that set it, not main's tip, so a PR merged after the release PR stays out
# of the release. A pushed go/ tag can never be moved (every consumer's go.sum
# records its hash), which is why each guard here refuses rather than guesses.
set -euo pipefail
cd "$(dirname "$0")/.."

remote=${REMOTE:-origin}
# Go refuses leading zeros in a module version.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

die() { echo "release: $*" >&2; exit 1; }

# version_at <commit> <package dir>
version_at() {
  git show "$1:$2/package.json" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).version))'
}

# semver_gt <a> <b>: whether a > b (a prerelease sorts below its release).
semver_gt() {
  A=$1 B=$2 node -e '
    const p = v => { const [core, pre] = v.split("-"); return [...core.split(".").map(Number), pre === undefined ? 1 : 0, pre ?? ""] }
    const a = p(process.env.A), b = p(process.env.B)
    for (let i = 0; i < 5; i++) if (a[i] !== b[i]) process.exit(a[i] > b[i] ? 0 : 1)
    process.exit(1)'
}

fetch_main() {
  local out
  # --tags too: prepare's PR body lists the commits since the last go/ tag.
  out=$(git fetch --tags "$remote" main 2>&1) || die "can't fetch main from $remote: $out"
  git rev-parse FETCH_HEAD
}

# remote_tag_commit <tag>: the commit a tag on the remote points at, or empty. An
# annotated tag's own ref names the tag object; only its ^{} line, which ls-remote
# lists only when asked for by name, names the commit.
remote_tag_commit() {
  local out
  out=$(git ls-remote --tags "$remote" "refs/tags/$1" "refs/tags/$1^{}") || die "can't list tags on $remote"
  awk 'NR==1{c=$1} /\^\{\}$/{c=$1} END{print c}' <<<"$out"
}

# gh_repo: the remote's owner/name for gh, which would otherwise pick a repo by its
# own rules (this checkout also has the archived predecessor as a remote).
gh_repo() {
  local url
  url=$(git remote get-url "$remote" 2>/dev/null || echo "$remote")
  if [[ $url =~ github\.com[:/]([^/]+/[^/]+)$ ]]; then echo "${BASH_REMATCH[1]%.git}"; fi
}

prepare() {
  local v=${1:-}
  [[ $v =~ $semver ]] || die "usage: release.sh prepare X.Y.Z"
  if ! git diff --quiet || ! git diff --cached --quiet; then die "the working tree has uncommitted changes"; fi
  # GitHub refuses a push carrying a private email (GH007).
  case $(git var GIT_COMMITTER_IDENT) in
    *@users.noreply.github.com\>*) ;;
    *) die "your git committer email must be your GitHub noreply address; TxnLab/zerosignal refuses others" ;;
  esac

  local base current latest t branch=release/v$v
  base=$(fetch_main)
  current=$(version_at "$base" ts)
  semver_gt "$v" "$current" || die "$v is not above main's $current"
  latest=$(git tag --list 'go/v*' | sed 's|^go/v||' | { grep -E "$semver" || true; } | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
  if [ -n "$latest" ]; then semver_gt "$v" "$latest" || die "$v is not above the latest release, $latest"; fi
  for t in "go/v$v" "ts/v$v" "sdk/v$v"; do
    [ -z "$(remote_tag_commit "$t")" ] || die "$t already exists on $remote"
  done
  git rev-parse --verify --quiet "refs/heads/$branch" >/dev/null && die "branch $branch already exists locally"
  [ -z "$(git ls-remote --heads "$remote" "refs/heads/$branch")" ] || die "branch $branch already exists on $remote"

  local start
  start=$(git symbolic-ref --quiet --short HEAD || git rev-parse HEAD)
  trap 'echo "release: prepare stopped partway. To start over: git switch $start && git branch -D $branch, plus git push $remote --delete $branch if it was pushed." >&2' ERR
  git switch --quiet -c "$branch" "$base"
  V=$v node -e '
    const fs = require("fs")
    for (const f of ["ts/package.json", "sdk/package.json"]) {
      const s = fs.readFileSync(f, "utf8")
      const out = s.replace(/("version"\s*:\s*")[^"]*(")/, `$1${process.env.V}$2`)
      if (out === s) { console.error(`no version field in ${f}`); process.exit(1) }
      fs.writeFileSync(f, out)
    }
    const c = fs.readFileSync("CHANGELOG.md", "utf8")
    let n = 0
    const out = c.replace(/^(### .*)\(unreleased\)$/gm, (_, h) => { n++; return `${h}(${process.env.V})` })
    fs.writeFileSync("CHANGELOG.md", out)
    console.log(`CHANGELOG: ${n} heading(s) relabelled (unreleased) -> (${process.env.V})`)
  '
  ./scripts/check-lockstep.sh
  git add ts/package.json sdk/package.json CHANGELOG.md
  git commit --quiet -m "ts, sdk: $v"
  git push --quiet -u "$remote" "$branch"

  local last log repo
  last=$(git describe --tags --abbrev=0 --match 'go/v*' "$base" 2>/dev/null || true)
  log=$(git log -50 --format='- %s' "${last:+$last..}$base")
  [ -n "$log" ] || log="- (no commits)"
  local body="Lockstep release $v of \`@txnlab/zs-proto\`, \`@txnlab/zerosignal\` and the Go module.

Since ${last:-the first release}:
$log

After merge: \`make release-tag\`."
  repo=$(gh_repo)
  if command -v gh >/dev/null && [ -n "$repo" ]; then
    gh pr create --repo "$repo" --base main --head "$branch" --title "ZeroSignal SDK $v" --body "$body"
  else
    echo "Open a PR from $branch into main titled \"ZeroSignal SDK $v\"."
  fi
  trap - ERR
  echo "You are on $branch. Next: squash-merge the PR, then run 'make release-tag'."
}

tag() {
  local tip v sdkv commit
  tip=$(fetch_main)
  v=$(version_at "$tip" ts)
  sdkv=$(version_at "$tip" sdk)
  [ "$v" = "$sdkv" ] || die "main has ts/ at $v and sdk/ at $sdkv; they must match"
  [[ $v =~ $semver ]] || die "main's version $v isn't X.Y.Z"

  # The release is the commit that set the version: walk main's first parents back
  # to it, so commits merged after the release PR aren't swept into the tag.
  commit=$tip
  while git rev-parse --verify --quiet "$commit^" >/dev/null && [ "$(version_at "$commit^" ts)" = "$v" ]; do
    commit=$(git rev-parse "$commit^")
  done

  local t existing todo=()
  for t in "go/v$v" "ts/v$v" "sdk/v$v"; do
    existing=$(remote_tag_commit "$t")
    if [ -n "$existing" ]; then
      [ "$existing" = "$commit" ] || die "$t is on $remote at ${existing:0:8}, but the commit that set $v is ${commit:0:8}; nothing pushed"
    else
      todo+=("$t")
    fi
  done
  if [ ${#todo[@]} -eq 0 ]; then
    echo "v$v is already tagged at $(git log -1 --format='%h %s' "$commit")."
    echo "To release a new version, merge a release PR first (make release-pr VERSION=X.Y.Z)."
    return
  fi

  echo "Tagging $(git log -1 --format='%h %s' "$commit")"
  local after
  after=$(git rev-list --count --first-parent "$commit..$tip")
  [ "$after" = 0 ] || echo "  (main has $after later commit(s); they are not in v$v)"
  echo "  ${todo[*]}"
  if [ "${YES:-}" != 1 ]; then
    local ok
    read -r -p "Push these tags to $remote? A pushed go/ tag can never be moved. [y/N] " ok
    case $ok in y | Y | yes | YES) ;; *) die "nothing pushed" ;; esac
  fi
  for t in "${todo[@]}"; do
    if git rev-parse --verify --quiet "refs/tags/$t" >/dev/null; then
      [ "$(git rev-parse "$t^{commit}")" = "$commit" ] || die "local tag $t points elsewhere; delete it first (git tag -d $t)"
    else
      git tag "$t" "$commit"
    fi
  done
  # Exactly these tags, all or none: GitHub starts no workflow for a push of more
  # than three tags, and followTags would add any other annotated tag.
  git push --quiet --atomic --no-follow-tags "$remote" "${todo[@]/#/refs/tags/}"
  echo "Pushed ${todo[*]}. release.yml stages each npm package whose tag was pushed."
  echo "Approve @txnlab/zs-proto first, then @txnlab/zerosignal (npmjs.com Staged Packages, or 'npm stage approve <id>')."
  echo "Check progress with 'make release-status'."
}

status() {
  local v=${1:-} tip t c repo
  if [ -z "$v" ]; then
    tip=$(fetch_main)
    v=$(version_at "$tip" ts)
  fi
  echo "v$v"
  for t in "go/v$v" "ts/v$v" "sdk/v$v"; do
    c=$(remote_tag_commit "$t")
    printf '  %-12s %s\n' "$t" "${c:-missing}"
  done
  repo=$(gh_repo)
  if command -v gh >/dev/null && [ -n "$repo" ]; then
    echo "release.yml:"
    gh run list --repo "$repo" --workflow release.yml --limit 6 \
      --json headBranch,status,conclusion --jq ".[] | select(.headBranch | endswith(\"v$v\")) | \"  \(.headBranch)  \(.status) \(.conclusion)\""
  fi
  echo "npm:"
  for p in @txnlab/zs-proto @txnlab/zerosignal; do
    printf '  %-20s %s\n' "$p" "$(npm view "$p@$v" version 2>/dev/null || echo 'not installable yet')"
  done
  printf 'go:\n  %s\n' "$(cd go && GOWORK=off GOFLAGS=-mod=mod GOPRIVATE='github.com/TxnLab/*' \
    go list -m "github.com/TxnLab/zerosignal/go@v$v" 2>/dev/null || echo 'not resolvable yet')"
}

cmd=${1:-}
shift || true
case $cmd in
  prepare) prepare "$@" ;;
  tag) tag ;;
  status) status "$@" ;;
  *) die "usage: release.sh prepare X.Y.Z | tag | status [X.Y.Z]" ;;
esac
