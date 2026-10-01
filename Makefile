# Makefile for proto/ — the ZeroSignal protocol module.
#
# proto/ carries two parallel implementations that must stay byte-compatible:
#   go/  — github.com/TxnLab/zerosignal/go    (canonical impl; generates the golden vectors)
#   ts/  — @txnlab/zs-proto                   (browser impl; mirrors the vectored go/ packages)
#
# testdata/*.json are the cross-impl golden fixtures: regenerated from the Go
# side (`make update-vectors`) and consumed read-only by both test suites — each
# go/<pkg>/*vectors_test.go bytes.Equal-checks its fixture, and the matching
# ts/test/*-vectors.test.ts loads it. So a green `make test` means go/, ts/, and
# the shared fixtures all agree.

GO   ?= go
PNPM ?= pnpm

.PHONY: test test-go test-ts verify-vectors update-vectors update-sealed-vectors \
	check-vector-generators vet typecheck

# Default goal: run both implementations' suites. test-go includes every
# Test*Vectors, which fails if its fixture has drifted from current Go output, so
# vector-staleness is caught here too.
test: check-vector-generators test-go test-ts

test-go:
	cd go && $(GO) test ./... -count 1

test-ts: ts/node_modules
	cd ts && $(PNPM) test

# Read-only check that every testdata fixture matches what the current Go code
# emits. No -update — on drift it fails with the "run ... -update" hint. This is
# a subset of test-go, exposed on its own for CI / quick local checks.
verify-vectors:
	cd go && $(GO) test ./... -run 'Vectors$$' -count 1

# Fails when a Test*Vectors generator has no line below, which is how three of
# them came to be silently skipped by update-vectors.
check-vector-generators:
	./scripts/check-vector-generators.sh

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
	cd go && $(GO) test ./inject     -run TestToolGrowthVectors     -update
	cd go && $(GO) test ./inject     -run TestDialectVectors        -update
	cd go && $(GO) test ./wire       -run TestStreamTerminalVectors -update
	cd go && $(GO) test ./attest     -run TestVectors               -update
	cd go && $(GO) test ./attest     -run TestComposeVectors        -update-compose

# testdata/sealed_vectors.json is CAPTURED, not derived: sealing draws a fresh
# nonce per call and age-wrapping is randomized, so regenerating it always
# produces a different file even with no code change. That churn is meaningless —
# regenerate it only when the response framing actually changed, which is why it
# is not part of update-vectors.
update-sealed-vectors:
	cd go && $(GO) test ./wire       -run TestSealedVectors         -update

vet:
	cd go && $(GO) vet ./...

typecheck: ts/node_modules
	cd ts && $(PNPM) typecheck

# Install (or refresh) the TS package's dependencies so `make test` works from a
# clean checkout and re-installs when the lockfile changes.
ts/node_modules: ts/package.json ts/pnpm-lock.yaml
	cd ts && $(PNPM) install --frozen-lockfile
	@touch ts/node_modules
