#!/usr/bin/env bash
# Generates the typed escrow app client from the in-repo ARC-56 into $1.
#
# `pnpm gen:client` writes the committed copy; `make check-escrow-client` writes
# to a scratch file and compares, so an ARC-56 synced from contracts/ without a
# regeneration fails CI instead of shipping a client for the previous contract.
set -euo pipefail
out="${1:?usage: gen-escrow-client.sh <output.ts>}"
cd "$(dirname "$0")/.."
pnpm exec algokitgen generate -m minimal -a ../go/escrow/ZeroSignalEscrow.arc56.json -o "$out" >/dev/null
node scripts/postprocess-escrow-client.mjs "$out"
