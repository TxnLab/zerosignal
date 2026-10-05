# Makefile for proto/ — the ZeroSignal protocol module.
#
# proto/ carries two parallel implementations that must stay byte-compatible:
#   go/  — github.com/TxnLab/zerosignal/go    (canonical impl; generates the golden vectors)
#   ts/  — @txnlab/zs-proto                   (browser impl; mirrors the vectored go/ packages)
#
# and the TypeScript payer SDK, sdk/ (@txnlab/zerosignal), the twin of go/zs. ts/
# and sdk/ are one pnpm workspace with one lockfile at this directory's root;
# sdk/ builds against ts/'s dist, as a consumer of the published package would.
#
# testdata/*.json are the cross-impl golden fixtures. Most are DERIVED: regenerated
# from the Go side (`make update-vectors`), each go/<pkg>/*vectors_test.go
# bytes.Equal-checks its fixture, and the matching ts/test/*-vectors.test.ts loads
# it. Two are CAPTURED sealing output, checked by opening rather than byte
# comparison: sealed_vectors.json (Go seals, TS opens) and ts_sealed_vectors.json
# (TS seals, Go opens) — see update-sealed-vectors below. So a green `make test`
# means go/, ts/, and the shared fixtures all agree.

GO   ?= go
PNPM ?= pnpm

.PHONY: test test-go test-ts test-sdk build-ts check-lockstep verify-vectors update-vectors update-sealed-vectors \
	update-ts-sealed-vectors check-vector-generators check-no-hayai check-gofmt check-escrow-client vet typecheck

# Default goal: run both implementations' suites. test-go includes every
# Test*Vectors, which fails if its fixture has drifted from current Go output, so
# vector-staleness is caught here too.
test: check-vector-generators check-no-hayai check-lockstep check-escrow-client test-go test-ts test-sdk

test-go:
	cd go && $(GO) test ./... -count 1

test-ts: node_modules
	cd ts && $(PNPM) test

# The typecheck runs here too: sdk/'s vocabulary test checks its lists against
# their types at compile time, which vitest alone does not.
test-sdk: build-ts
	cd sdk && $(PNPM) typecheck && $(PNPM) test

# ts/ and sdk/ release as a matching pair; see the script. The test runs first,
# for the same reason as check-no-hayai's.
check-lockstep:
	./scripts/check-lockstep.test.sh
	./scripts/check-lockstep.sh

# sdk/ resolves @txnlab/zs-proto to ts/dist, so it needs a current build.
build-ts: node_modules
	cd ts && $(PNPM) build

# Read-only check that every testdata fixture matches what the current Go code
# emits, and that Go still opens the TS-sealed fixture. No -update — on drift it
# fails with the "run ... -update" hint. This is a subset of test-go, exposed on
# its own for CI / quick local checks.
verify-vectors:
	cd go && $(GO) test ./... -run 'Vectors$$|TestOpensTSSealedArtifacts' -count 1

# Fails when a Test*Vectors generator has no line below, which is how three of
# them came to be silently skipped by update-vectors.
check-vector-generators:
	./scripts/check-vector-generators.sh

# Fails when sdk/'s committed escrow client is not what the in-repo ARC-56
# generates, which is how the client's copy came to embed a stale contract.
check-escrow-client: node_modules
	@tmp="$$(mktemp -d)" || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	sdk/scripts/gen-escrow-client.sh "$$tmp/ZeroSignalEscrowClient.ts" || exit 1; \
	cmp -s "$$tmp/ZeroSignalEscrowClient.ts" sdk/src/escrow/generated/ZeroSignalEscrowClient.ts || \
	{ echo "sdk escrow client is stale (run: pnpm -C sdk gen:client)"; exit 1; }

# Fails when the old project name reappears in the published code. The test
# runs first: on the real tree the guard only ever passes, so the test is what
# shows it can still fail.
check-no-hayai:
	./scripts/check-no-hayai.test.sh
	./scripts/check-no-hayai.sh

# Regenerate every testdata/*.json fixture from the Go side after an intentional
# change (e.g. a new field in Ticket/UsageReceipt). Re-run `make test` afterwards
# so the TS side re-checks against the new fixtures.
#
# Each generator lives in the package it pins and registers its own -update flag,
# so these must be enumerated per package — `go test ./... -update` fails on every
# package that doesn't define the flag. Adding a new generator means adding a line
# here (check-vector-generators enforces it), and a generator with its own flag
# name — attest's -update-compose — must be invoked with that flag: -update is
# also defined in that package, so the wrong one regenerates nothing and exits 0.
update-vectors:
	cd go && $(GO) test ./ticket     -run TestVectors               -update
	cd go && $(GO) test ./imageprice -run TestVectors               -update
	cd go && $(GO) test ./pricing    -run TestVectors               -update
	cd go && $(GO) test ./tokenize   -run TestVectors               -update
	cd go && $(GO) test ./selection  -run TestSelectionVectors      -update
	cd go && $(GO) test ./transient  -run TestTransientVectors      -update
	cd go && $(GO) test ./steering   -run TestSteeringVectors       -update
	cd go && $(GO) test ./inject     -run TestToolGrowthVectors     -update
	cd go && $(GO) test ./inject     -run TestDialectVectors        -update
	cd go && $(GO) test ./inject     -run TestDetailsVectors        -update
	cd go && $(GO) test ./inject     -run TestPayerMutatorVectors   -update
	cd go && $(GO) test ./tools      -run TestPayerToolsVectors     -update
	cd go && $(GO) test ./wire       -run TestStreamTerminalVectors -update
	cd go && $(GO) test ./attest     -run TestVectors               -update
	cd go && $(GO) test ./attest     -run TestComposeVectors        -update-compose
	cd go && $(GO) test ./escrow     -run TestEscrowVectors         -update
	cd go && $(GO) test ./escrow     -run TestGroupVectors          -update
	cd go && $(GO) test ./zs         -run TestStreamEventVectors    -update
	cd go && $(GO) test ./zs         -run TestRetryVectors          -update
	cd go && $(GO) test ./zs         -run TestReconcileVectors      -update
	cd go && $(GO) test ./zs         -run TestVocabularyVectors     -update
	cd go && $(GO) test ./zs         -run TestBandingVectors        -update
	cd go && $(GO) test ./zs         -run TestDispatchVerdictVectors -update
	cd go && $(GO) test ./zs         -run TestRelayAttributionVectors -update

# testdata/sealed_vectors.json (Go seals, TS opens) and ts_sealed_vectors.json
# (TS seals, Go opens) are CAPTURED, not derived: sealing draws a fresh nonce per
# call and age-wrapping is randomized, so regenerating either always produces a
# different file even with no code change. That churn is meaningless — regenerate
# one only when the framing its sealer emits actually changed, which is why
# neither is part of update-vectors.
update-sealed-vectors:
	cd go && $(GO) test ./wire       -run TestSealedVectors         -update

update-ts-sealed-vectors: node_modules
	cd ts && ZS_UPDATE_TS_SEALED_VECTORS=1 $(PNPM) vitest --run test/ts-sealed-vectors.test.ts
	cd go && $(GO) test ./wire       -run TestOpensTSSealedArtifacts -count 1

vet: check-gofmt
	cd go && $(GO) vet ./...

# gofmt -l exits 0 even when it lists files, so a non-empty listing is the
# failure; it exits non-zero only on a file it can't parse, which vet misses
# under testdata/ or a build tag. Lives under vet because CI runs vet; nothing
# else checked formatting.
check-gofmt:
	@out="$$(cd go && gofmt -l .)" || exit 1; \
	if [ -n "$$out" ]; then echo "gofmt needed (run: cd go && gofmt -w .):"; echo "$$out"; exit 1; fi

typecheck: build-ts
	cd ts && $(PNPM) typecheck
	cd sdk && $(PNPM) typecheck

# Install (or refresh) the workspace's dependencies so `make test` works from a
# clean checkout and re-installs when the lockfile changes.
node_modules: package.json ts/package.json sdk/package.json pnpm-lock.yaml
	$(PNPM) install --frozen-lockfile
	@touch node_modules
