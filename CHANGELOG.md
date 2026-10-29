# ZeroSignal wire protocol changelog

History of `wire.ProtoVersion` — the `<major>.<minor>` generation each build advertises.
Newest first.

- The **rules** for what a major vs. a minor bump means, and how `proto_version` relates to
  the cryptographic domain tags, live in [`SPEC.md` §3c "Protocol version
  negotiation"](./SPEC.md). They are not repeated here.
- The **current value** is the `ProtoVersion` constant in
  [`go/wire/version.go`](./go/wire/version.go), mirrored in `ts/src/wire/version.ts`.

Two recurring notes, true of every entry below unless it says otherwise:

- **Bumping the major IS the gating mechanism.** There is no per-feature capability flag for
  a breaking change: `ProtoVersionCompatible` is major-equality, so the version filter drops
  incompatible peers from a candidate set up front rather than letting them fail after a
  wasted reserve.
- **A signing-tag change is not a contract redeploy.** The tags are off-chain only — the
  `ZeroSignalEscrow` contract verifies a digest passed as an ABI arg and never recomputes the
  pre-image.

---

## Unversioned — verifier behavior

Changes to this module that consumers depend on but that do **not** move `ProtoVersion`, so
they carry no generation number and no peer ever advertises them. They still ride both
publish gates, and a consumer sees them only after a pin bump. Newest first, dated.

Kept above the version history rather than inside it because a heading here that named a
generation would make "does this peer speak it?" unanswerable — nothing on the wire carries
the answer.

### 2026-10-30 — the Solana Config's grace and lifetime bounds are retired (unreleased)

`zs_escrow`'s `open` bounds neither grace nor expiry, as Algorand's `open()` doesn't: any
future `expires_at`, any grace, 0 taking `default_grace`. The payer's offer check still
refuses a grace other than 0. The Config keeps the three fields' bytes, so the decoders read
them as `RetiredMaxGrace`, `RetiredMaxTicketLifetime` and `RetiredMinGrace` ↔
`retiredMaxGrace`, `retiredMaxTicketLifetime` and `retiredMinGrace`, and `InitializeArgs` and
`SetConfigArgs` lose `MaxGrace`, `MinGrace` and `MaxTicketLifetime` ↔ `maxGrace`, `minGrace`
and `maxTicketLifetime`. A `set_config` built by an earlier release is read by the upgraded
program with its fields shifted, since Anchor ignores trailing argument bytes, so send it
only from this release on.

### 2026-10-29 — a Solana node's SOL/USD rate (0.13.0)

A Solana node reports its SOL/USD quote as `sol_usd_price`, in the sealed reserve response and
in `/v1/zs/details` beside `sol_usd_at`, as an Algorand node reports `algo_usd_price`. Each
payer reads only the rate for the coin its deployment's fees are paid in (`nativeUSD` ↔
`nativeUsd`), so on Solana `ReceiptVerified.NativeUSD` ↔ `nativeUsd`, `X-Zs-Fees-Usd-Rate` and
`X-Zs-Fees-Usd` now carry the fees' dollar value, where they were 0 or absent. `AlgoUSD` ↔
`algoUsd` stays 0 off Algorand. The fields are additive: a node that omits them prices
nothing, as before. `ReservedTicket` gains `SOLUSDPrice` ↔ `solUsdPrice` (optional in TS, so a
host's own `ReserveClient` still compiles).

### 2026-10-27 — what a Solana payer's host needs (0.12.0)

The SDKs add the reads and calls a host's wallet commands make on the Solana rail, as
Algorand's hosts make them through the escrow client. `SolanaWallet` now has a protocol fee
rate, the Config's `fee_bps` read each time (`ProtocolFeeBps` ↔ `protocolFeeBps`), so a
Solana payer's `/v1/models` carries a price and its reserve check bounds the fee by the
Config's rather than `pricing.ProtocolFeeBpsMax`. It also gains `USDCAccount` ↔ `usdcAccount`,
`EnsureUSDCAccount` ↔ `ensureUsdcAccount` (the idempotent associated token account create),
and `RecoverTicket` ↔ `recoverTicket`, which classifies a fresh read of one of the payer's
tickets, its deadline padded by the reconciler's 15 s skew, and sends the `refund_inactive`
or `settle_lapsed` it allows, built from that same read. The rent pool gains
`ReadSolanaRentPool` ↔ `readSolanaRentPool`, which needs no signer, with the available, free
and backed slots, and `Withdraw` / `Close` ↔ `withdraw` / `close`, which refuse before
signing on no pool, an amount above what the pool holds over its own rent, or a close with
tickets open. The wallet reaches its pool through `RentPool` ↔ `rentPool`, and
`CloseRentPool` ↔ `closeRentPool` closes it and clears the ready latch, so the next open tops
the pool up again. The TS package root now exports `SolanaWallet`, `SolanaRentPool`,
`SolanaTicketGoneError` and `readSolanaConfig`. `FetchSolanaPayerTickets` ↔ `fetchSolanaPayerTickets` lists a payer's live
tickets with `getProgramAccounts` filtered on the payer at `TicketPayerOffset` ↔
`TICKET_PAYER_OFFSET` (131, pinned against the account fixtures), each placed at its node.
Go only: `go/wallet` records a 24-word wallet's Solana address in `wallet.json`
(`solana_address`, backfilled on the next read of an older wallet), `go/solana/rpc`
gains `RequestAirdrop` and `FaucetCluster`, `SolanaRentPoolStatus` gains `Shortfall` and
`Excess`, Solana's `DepositShortfall` and `DepositExcess`, and `go/keystore` gains
`ReadSolanaKeypairFile`, which reads a `solana-keygen` keypair file and refuses one whose
public half doesn't match its seed. Both languages gain the SPL `MintTo` builder
(`solana.MintTo` ↔ `mintTo`), pinned in `solana_codec_vectors.json`. No wire shape changes.

### 2026-10-27 — free credits: what the node does with them (0.12.0)

SPEC § 3a "Free credits" describes the node's check, built in zs-node: a free reserve's
credit is checked at reserve and spent when its turn is consumed, so a second turn on one
credit is refused `409 free_credit_spent` at its sealed request with its ticket gone; a
credit on a priced reserve is ignored; and an issuer seen with two day keys for one epoch
has its credits refused as `free_credit_invalid` for the rest of it, so an issuer must keep
each day key across restarts. "Free-ticket quota", "On Solana", says what a credit buys:
while a node trusts an issuer, free turns without one may spend only a share of its budget
and of its places in flight. Admission step 4 checks the free cap again, so a free turn can
now be refused `429 no_capacity` at its sealed request. The reserve and error tables name
the new refusals. Two residuals: the node's spent set, day keys and bars are in memory, so a
restart forgets them, and the payer's own check for a second day key is still unbuilt. No
wire shape changes.

### 2026-10-27 — free credits: the payer fetches and attaches them (0.12.0)

The SDKs carry a free credit on a free Solana reserve (SPEC § 3a "Free credits"). A host
names the issuers it can reach in `zs.Config.FreeCredits` ↔ `Config.freeCredits`, with
`zs.HTTPCreditIssuer` ↔ `httpCreditIssuer` for the issue wire and a `CreditStore` port
(in memory by default); with none, which is the default, nothing changes. The payer fetches
a batch of 3 credits for a node when a reserve there first needs one, under the one day key
it verified for that day, and attaches one when the node trusts the issuer and prices the
model at nothing (`creditIssuersFor` ↔ `creditIssuersFor`, pinned per model by
`operator_vectors.json`). `ticket.ReserveRequest` gains `free_credit`, outside the payer
signature's digest. A node's `400 free_credit_invalid` and `409 free_credit_spent`
(`freecredit.CodeFreeCreditInvalid` / `CodeFreeCreditSpent`, pinned in
`free_credit_vectors.json`) are refusals with no strike (`dispatch_verdict_vectors.json`).
On either the payer drops the credit and asks the node once more, with another credit after
a spent one and with none after an invalid one, and a node that refuses a credit it was sent
is sent none for the rest of the day. `zs.Operator` gains
`FreeCreditIssuers`, and `sdk_vocabulary_vectors.json` the batch, fetch timeout and failure
backoff. The stub node serves an issuer, checks the credits it is sent, and spends one when
its turn is consumed, and both e2e
suites cover a free turn with a credit, with the issuer down, and a paid turn.

### 2026-10-26 — free credits: the token, the details field, the presets (0.12.0)

A new protocol package, `go/freecredit` ↔ `@txnlab/zs-proto/freecredit` (subpath only), holds
the free credit (SPEC § 3a "Free credits"): an RFC 9474 blind signature
(`RSABSSA-SHA384-PSS-Deterministic`, via `cloudflare/circl` and `@cloudflare/blindrsa-ts`)
by an issuer's RSA day key over a message naming the deployment, the node's routing pair,
the UTC day and a nonce. The issuer's Ed25519 key certifies each day key for its deployment
and day, and issuers and nodes take only the current day and, within 10 minutes of
midnight, the neighbouring one. It has the payer's blind and finalize, the node's verify
with a typed refusal, the spent-set key and the issuer's day signer (both Go only), and the
issue wire's types. `testdata/free_credit_vectors.json` pins the message and certificate bytes,
the accepted epochs, the day-key rules, the credit's JSON and each refusal, and
`testdata/rfc9474_pss_deterministic.json`, copied from circl, pins the variant in both
languages. `/v1/zs/details` gains `free_credit_issuers`, the issuer keys a node trusts (Go
`inject.OperatorDetails.FreeCreditIssuers`, parsed by the TS details parser). The Solana
presets gain default issuers (`zsescrow.Cluster.FreeCreditIssuers`, read through
`zs.SolanaClusterFreeCreditIssuers` ↔ `solanaClusterFreeCreditIssuers`): localnet a test
key whose private half is committed beside the stub node, marked loopback-only, which
`zsescrow.TrustedFreeCreditIssuers` drops for a node whose RPC is off the machine; devnet
none yet.
`go run ./cmd/freecreditkey -out <file>` makes an issuer key. Nothing sends or checks a
credit yet.

### 2026-10-26 — a free Solana turn opens nothing (0.12.0)

A Solana ticket at `max_price` 0 has no on-chain open: the program refuses a zero-price
open, and the free tier there is off chain (SPEC § 3a "Free turns on Solana"). Both SDKs
skip the wallet's open for one (`opensOnChain` ↔ `opensOnChain` in `rail.go` ↔ `rail.ts`):
they sign and hand over nothing, bind an empty `tx_id` in the admission tag and the response
AAD, release the spend reservation at once (nothing is locked), and pass the receipt check
no handle, so it sends no ack, protest or journal row, and the refund watchdog tracks
nothing. `payment.committed` still fires for the turn once it is sealed, with an empty
`OpenTxID` / `openTxId` and no fees, so a host's "the node admitted us" line holds on both
rails, but it leaves the turn unpaid: an error after it has `Paid` false and no `Ticket`,
since nothing is locked. A host should not open a settlement window for an empty
`openTxId`. An Algorand free ticket still opens at zero under the contract's quota.

A node rations free Solana turns itself with a daily token budget, refusing with the new
`429 free_budget_exhausted` (`transient.BusyCodeFreeBudgetExhausted` ↔
`BusyCode.FreeBudgetExhausted`). The SDKs fail over from it, still re-sweep a sibling that
was only unreachable, and, when no node was busy or left unreachable, end the turn with the new error code
`free_budget_exhausted` (`KindFunds`, not retryable, rendered 403 like
`free_quota_exhausted`), with a `Retry-After` to the next 00:00 UTC, instead of
`operators_busy`. `dispatch_verdict_vectors.json` gains a `free_budget_spent` field. A payer
from before this change fails a free Solana turn at its open, since the wallet refuses a
ticket with no offer, and reads `free_budget_exhausted` as a busy code it may not re-ask,
so it reports `operators_busy`.

### 2026-10-25 — a Solana ticket stores its ticket id (0.12.0)

The `zs_escrow` program's `Ticket` account stores the id its address derives from
(`Ticket.TicketID` ↔ `ticketId`, 16 bytes after `freeze_origin`; every earlier offset stays
put). The address is a hash of the id and can't give it back, while the wire, receipts, the
node's ledger and the payer's journal all name a ticket by its id, so a walk of a node's
ticket accounts could end a ticket but not say which one it was. An Algorand box's name is
its ticket id, so its walk always could. The account grows
from 275 to 291 bytes (`TicketSize` ↔ `TICKET_SIZE`), so a ticket's rent rises from 2,804,880
to 2,916,240 lamports, which the rent pool's sizing reads. A deployed program and its tickets
must be replaced, since old accounts no longer decode; devnet and testnet held none.

### 2026-10-25 — the aggregate's tags are a sorted set (0.12.0)

Both SDKs' `AllModelDetails` ↔ `allModelDetails` (Go's `aggregateModelDetails` ↔ `aggregateModelDetails` in
`sdk/src/registry/aggregate.ts`) now fold each model's tags: trimmed, lowercased (Go's
`strings.ToLower` / `TrimSpace`, JS `toLowerCase` / `trim`), blanks dropped, one entry each, in
code point order. Before, `NSFW` and `nsfw` from two
operators both listed, a repeat within one operator's list was kept, and the order followed
operator iteration, so it moved between refreshes. Modalities and `allowed_efforts` still union
as before. The per-operator `/v1/zs/operators` keeps each operator's tags verbatim. Pinned by
`catalog_aggregate_vectors.json` (SPEC § 3c).

### 2026-10-25 — the payer's catalog endpoints carry model tags (0.11.0)

The Go handler's `/v1/zs/details` gives each model the union of its operators' `tags`, and
`/v1/zs/operators` gives each operator's own, as SPEC § 3c describes. The registry already
merged them; neither endpoint emitted them. `zs-proxy models --tag` reads the aggregate, so
it needs this release.

### 2026-10-24 — `payer_usdc_account_unusable` ends the reserve sweep (0.11.0)

A Solana node refuses a reserve with `403 payer_usdc_account_unusable` when the payer's USDC
token account can't take a refund (missing, frozen, or not the payer's account of the escrow's
mint), since every ending refunds the payer through it (SPEC § 3a, the reserve's error table).
Only `payer_not_opted_in` still has the wallet recheck its deposit. Both SDKs now read it as they read `payer_not_opted_in`: a payer
refusal that every node gives alike, so the sweep stops at the first one and reports a `funds`
error with the node's message. Before this they read it as an ordinary 403 and asked every
other node in turn. SPEC also gains the Solana node's fee component of the minimum charge,
`zs.min_charge.lamports` at SOL/USD, which a payer bounds through the existing
`min_charge_microusdc`, and the Solana reserve's other rules: the payer signature is always
required and must be deployment-bound, and `409 ticket_id_taken` joins the transient vectors.

### 2026-10-24 — The Solana cluster presets move to `solana/zsescrow` (0.11.0)

The devnet and localnet presets (RPC endpoint and program id) are now
`zsescrow.ClusterPreset` / `Clusters` / `ClusterDevnet` / `ClusterLocalnet`, so a node reads them
without importing the payer SDK, as Algorand's presets live in `algod`. The `zs` names
(`SolanaClusterPreset`, `SolanaClusters`, `SolanaClusterDevnet`, `SolanaClusterLocalnet`) still
work and forward to them. `ClusterPreset` matches the name case-insensitively, as
`ResolveNetwork` always has, so `zs.SolanaClusterPreset("Devnet")` now finds devnet.

### 2026-10-23 — Solana confirmations work against Agave (0.11.0)

`getSignatureStatuses` sent an empty config object when the caller didn't ask for history, and
Agave refuses that object without its `searchTransactionHistory` field. The confirmation wait
(`rpc.Confirm` ↔ `confirmSignature`) polls that method, so against a real cluster a poll failed
instead of reporting the transaction's status. Both RPC clients now always send the field
(`solana_rpc_vectors.json` pins the params). `getMinimumBalanceForRentExemption` had the same
shape: Agave refuses its config object without `commitment`, so a call that names none now sends
no object. Every caller names one today, so nothing hit it. The fake
clusters every test ran against accepted the empty object; the local-validator suite
(`go/internal/solanastub`, README "Build & test") found it.

### 2026-10-23 — `zerosignal doctor` takes the Solana rail (0.11.0)

The TS command line took Algorand networks only. `--rail solana` with `--network devnet|localnet`,
`--rpc-url` and `--program` now runs the Solana doctor, setting the `Network` fields of those
names. The flags pass through to `resolveNetwork`, so each rail refuses the other's as a
`Network` does, and the command exits 2 on the mix. `--rail` defaults to `algorand`, so an
existing command line is unchanged. Go has no doctor command line in this module.

### 2026-10-23 — the doctor fails a paused escrow, on both rails (0.11.0)

Both contracts refuse every open while their admin has paused them (Algorand's `paus` global,
the Solana Config's `paused`), yet the doctor passed its `escrow` / `program` check on a paused
deployment. It now fails that check, naming the pause. The account checks after it still run,
since their readings still hold. `DoctorReadings.EscrowPaused` ↔ `escrowPaused` and
`SolanaDoctorReadings.ConfigPaused` ↔ `configPaused` carry the reading, and `doctor_vectors.json`
pins the verdict. On Algorand the flag comes from the same application fetch as the other
globals: `escrow.Client.Paused` ↔ `AlgodEscrowChain.paused()`, a snapshot as of `RefreshConfig`,
since `setPaused` toggles it at any time. A `paus` global of the wrong type now fails
`RefreshConfig`, as the other globals' do.

### 2026-10-23 — the doctor reads Solana (0.11.0)

`zs.Diagnose` ↔ `diagnose` on a Solana network read that rail for a base58 address, where they
refused it, and return the same `DoctorReport`. The checks are `SolanaDoctorChecks` ↔
`solanaDoctorChecks` over `SolanaDoctorReadings`, in order:
- `rpc`: the RPC answers (its block height).
- `program`: the program's Config reads, the cluster quotes a ticket's rent, and the Config's
  genesis hash, which every ack digest binds, is the one the RPC serves; an RPC on another
  cluster fails here.
- `sol`: the payer's lamports, and what is spendable above its own reserve. No SOL is a
  warning rather than Algorand's failure: the node pays the open's fee, so a payer whose rent
  pool is already at its working set still pays for requests.
- `usdc_account`: the payer's token account for the Config's mint exists and is not frozen.
- `usdc_balance`: as on Algorand.
- `rent_pool`: the ticket rent pool, judged by the wallet's own top-up plan
  (`planRentDeposit`), as `prepaid_pool` judges the MBR pool.
- `operators`: as on Algorand, against the lamports floor. `DoctorNode` gains
  `SignerSpendableLamports` ↔ `signerSpendableLamports`, and a node short of it is counted as
  "with a signing account short of fee SOL".

The `solanaCases` of `doctor_vectors.json` pin the checks' statuses and wording across the two.

### 2026-10-23 — Go loaders for a Solana payer key (0.11.0)

`keystore.LoadSolanaFromEnv` is `LoadFromEnv` for Solana: the same `<NAME>_MNEMONIC` and
`ZS_MNEMONIC_URLS` providers and timeout, each phrase derived at m/44'/501'/0'/0' by
`NewSolanaKeys`. `wallet.LoadSolanaPayer` is `LoadPayer`'s twin: it opens the same local
wallet and environment and returns a `SolanaPayer` whose `Signer` is a `zs.SolanaSigner`, so a
wallet's 24-word phrase pays as the address Phantom shows for it. A 25-word Algorand mnemonic
has no Solana key and is skipped; `NewSolanaKeys`, and so both loaders, now fail naming it
when Algorand mnemonics are all the providers held, as `New` fails on Solana phrases alone.
`SolanaPayer` carries no network: the wallet's descriptor names its Algorand address, so it
never says which Solana key is the wallet's (`ReadMetadata` still reads it).

### 2026-10-23 — a Client runs on Solana from its Network (0.11.0)

A Solana Network now resolves, and `New` ↔ `Client.create` build every part on it, so a host
needs only the network and the payer's Solana key:
- **Network.** `Rail` ↔ `rail` set to Solana reads `Network.Solana` (`Cluster`, `RPCEndpoint`,
  `Program`) ↔ `network`, `rpcEndpoint` and `program`. There are two presets, `devnet` and
  `localnet` (`SolanaDevnet()` / `SolanaLocalnet()` ↔ `solanaDevnet()` / `solanaLocalnet()`),
  both on program `2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1`, the localnet one the cluster
  contracts-solana's `make localnet` starts. There is no zero-value cluster: a Solana Network
  names its cluster or its endpoint, and an endpoint alone sets the program. The endpoint is
  used verbatim. The USDC mint is read from the program's Config.
- **Each rail refuses the other's fields.** A Solana setting on an Algorand Network, or an algod
  setting or app id on a Solana one, is `invalid_config`, so a Solana setting without the rail
  fails rather than paying on Algorand mainnet. The zero Network is still Algorand mainnet.
- **The deployment key** is `solana-<cluster>-<program>`, or `solana-custom-<program>` for an
  endpoint alone. Unlike an app id the program is the same on every cluster, so the cluster the
  config names is the label. `deployment_vectors.json` pins the keys, and
  `sdk_vocabulary_vectors.json` the presets.
- **The payer's key** is `Config.SolanaSigner` ↔ `solanaSigner` on Solana, and `Signer` ↔
  `signer` on Algorand; a Config carrying the other rail's signer is refused. TS `Config.signer`
  is optional now, and `ResolvedConfig` carries both and `payerSigner`, the one the rail signs
  with. A host that read the payer's address from `client.config.signer.address` reads
  `client.config.payerSigner.address`.
- **What is built:** one RPC client, the `SolanaWallet` on the Config's mint, the reserve client
  signing as the Solana payer and binding the deployment from the cluster's genesis hash and the
  program, and discovery through `SolanaChainReader`, which also runs the lamports balance pass.
  Confirmations poll: there is no pubsub socket, since one ends on its first drop. The Go RPC
  client takes the environment proxy only under `UseEnvProxy`, as algod's does. TS exports
  `solanaRpc(config)`, and `buildDiscovery` takes a `ChainReader` in place of algod.
- `Network.Name()` is the preset on either rail, which the funding messages and the handler's
  funding hint read.
- **TS types widen.** `Network.network` and `ResolvedNetwork.network` take `SolanaClusterName`
  (`devnet`) too, so a switch over them or an index into a `Record<NetworkName, …>` needs the
  new case, and a Solana field without `rail: 'solana'` compiles and is refused when resolved.
- An all-zero program id is the unset one in both SDKs, as Go's zero `solana.PublicKey` is.

A `SolanaSigner` ↔ `solanaSigner` left on an Algorand config is ignored by the doctor, as the
`Signer` is (see "the doctor reads Solana").

### 2026-10-23 — `no_funded_operator` and the funding remedies name the rail's coin (0.11.0)

Messages a payer reads named ALGO on every rail. On a Solana Client they now name the Solana
rail's own:
- The `no_funded_operator` refusal and the two pin refusals behind it (a `previous_response_id`
  pin, a strict tool-affinity pin) say "less than 10120 lamports", the floor
  `MinSignerSpendableLamports` ↔ `MIN_SIGNER_SPENDABLE_LAMPORTS` gates on, where they said
  "less than 5 ALGO".
- `mbr_pool_underfunded` says the wallet "needs more SOL (not USDC) to fund the prepaid ticket
  rent pool", where it said ALGO and the ticket-MBR pool.
- The default `Remedies.Fund` ↔ `remedies.fund` says "fund the payer address: SOL for fees and
  the ticket rent pool, and USDC for requests", with no USDC opt-in, and the default
  `RecoverTicket` ↔ `recoverTicket` points at the ticket account and `refund_inactive` /
  `settle_lapsed` rather than the box. Go's default `RaiseSlots` names
  `SolanaWalletConfig.DepositSlots`. A host's own remedies are used as given.

An Algorand Client's messages are unchanged, byte for byte. The TS `DispatchDeps`, `PickDeps`
and `SealedDeps` take the rail as an optional `rail`, and `openFailure` as a last argument,
absent meaning Algorand.

### 2026-10-23 — a delivered Solana ack is confirmed by its ticket (0.11.0)

After a turn whose ack the payer handed the node, both SDKs now watch for the node's settle to
land and then drop the ticket's journal row, as they do on Algorand once the settle group
confirms. The node builds and sends that settle, so the payer has no transaction id to look up:
the watch reads the ticket account, for up to the watchdog's three minutes, past a blockhash's
life, and takes it closing after the watch saw it open as the settle landed. An account not seen
yet is no answer, since the node serves on an open still confirming, which can land after the
reply. So the account is also read once just before the ack goes to the node, which cannot
settle without it: an open seen there counts, and a settle that lands before the watch's first
read is still seen closing. That read holds the delivery up for at most two seconds. The watch
was skipped, so the row stayed until the reconciler forgot it after the ticket's expiry. A
settle that never lands, or one that lands before any read has seen the account open, leaves
the row to the reconciler, as before.

A closed account counts only as of a slot after the one the watch last saw it open at. A
provider balances reads across nodes slots apart, so a node behind the one that showed the
account can answer that it is missing. Each read therefore sends that slot as its
`minContextSlot`, through a new slot-aware read: `rpc.AccountAtReader`'s
`GetAccountInfoAt`, which `HTTPClient` implements, ↔ the optional
`SolanaRpc.getAccountInfoAt`, which `SolanaRpcClient` implements. Both clients now retry a
getAccountInfo refused with -32016 (minimum context slot not reached), as a node behind the
cluster. An RPC client without the slot-aware read gets no watch, and the row stays with the
reconciler as before.

`WaitSettles` ↔ `waitSettles` now waits for these watches too, as for Algorand's: usually a few
seconds, and up to the host's budget for a node slow to settle. A watch that never sees the
account open, as when the settle lands before any read has, runs the whole three minutes.
Closing the Client ends them and keeps the rows.

### 2026-10-23 — the reconciler sweeps Solana tickets (0.11.0)

The journal's reconciler in both SDKs now runs for a Solana wallet, which got none, and so did
not get the default in-memory journal either. It reads each row's ticket account where
Algorand reads the box, and decides as it does on Algorand: `refund_inactive` on an open ticket
past its deadline, `settle_lapsed` on a node's claim left past the lapse fallback, the payer's
own `ack` at the recorded receipt to re-fire a settle or to freeze a claim above it, and the
row forgotten once the ticket is gone or frozen. A node whose claim exceeds the receipt is
barred, as on Algorand. A Solana submit gets the watchdog's three-minute budget, so a refund or
lapse that confirms late still releases its spend reservation in the same sweep.

`decideSolanaTicket` ↔ `decideSolanaTicket` is the Solana wrapper over the reconciler's core
beside `decideTicket`. `reconcile_vectors.json` pins it: every case has a Solana twin, the
ticket account carrying the box's state or closed where there is no box, which must reach the
same action.

### 2026-10-23 — the refund watchdog on a Solana ticket (0.11.0)

The refund watchdog in both SDKs now tracks a Solana handle, which it left untracked. It reads
the ticket account where Algorand reads the box, and acts as it does on Algorand:
`refund_inactive` on a ticket past its deadline with no node claim, `settle_lapsed` on a node's
claim the node never lapsed, nothing on a ticket gone or frozen, and no lapse of a claim above
the receipt the node signed, whose node it bars. It first reads the ticket at expires_at plus
the Config's `default_grace`, which a payer's open takes, and the watchdog's margin, and waits
out the ticket's own deadline when that is later. A Solana refund or lapse waits for its
transaction to confirm, for up to three minutes, past a blockhash's life, where the watchdog
gives an Algorand call 30 seconds: cut short, a refund that landed late would never be reported
refunded, so its spend reservation would never be released.

The watchdog's read is rail-neutral now: each wallet hands it the ticket as a `settle.Ticket`
↔ `TicketView` with the amount of its pending claim, in place of the Algorand box.

### 2026-10-23 — the Solana handle's protest, refund, lapse and freeze (0.11.0)

A Solana ticket's handle now has every settle path an Algorand one has, each the payer's own
transaction, where each returned "not supported yet":

- **`Protest` ↔ `protest`** sends the receipt with the node's signature over its digest, by the
  key the ticket took at open, in an Ed25519 precompile instruction before the `protest`
  instruction (`solana.Ed25519Verify` ↔ `ed25519Verify`). It pays for two signatures, 10,000
  lamports. The program has no dispute excerpt, so the handle drops it. A reason above 255 is
  refused before signing.
- **A protest past the settle window** wraps `escrow.ErrProtestAfterDeadline`, as Algorand's
  revert does. TS throws `ProtestAfterDeadlineError`, which the receipt check reads beside the
  Algorand revert, so neither rail tries the freeze no settle could make either. The program's
  error code is read from a failed preflight or a landed failure (`rpc.TxCustomError` ↔
  `txCustomError`, `(*rpc.Error).TxErr` ↔ `SolanaRpcError.txErr`, `zsescrow.ErrPastDeadline` ↔
  `ERR_PAST_DEADLINE`).
- **`RefundInactive` / `SettleLapsed` ↔ `refundInactive` / `settleLapsed`** send
  `refund_inactive` / `settle_lapsed` over the ticket account, forfeiting the refund to the
  treasury when the payer's token account can't take it, as the ack does.
- **`freezeOverclaim`** sends the payer's ack at the receipt over a claim above it, and nothing
  over any other.
- **A protest that was sent and failed** reports its transaction id and fee in the turn's
  `Settlement`, as a failed ack does, since a Solana protest that lands and fails pays its fee.
  A freeze after it adds its own fee, under its id. An Algorand protest that fails has sent
  nothing, so its report is unchanged.

The program's protest fixtures in `solana_tx_vectors.json` now carry the node's signature.

### 2026-10-23 — dstack verifiers refuse debug TDs and pin the boot chain (0.10.0)

Both SDK verifiers, and every caller of `attest`, now run two checks that a dstack quote could
previously pass without:

- `VerifyNotDebug` ↔ `verifyNotDebug` refuses a quote whose TDATTRIBUTES "TD under debug"
  byte is non-zero. It runs after the vendor chain and before the replay.
- `VerifyBootChain` ↔ `verifyBootChain` runs after the OS-image check. MRTD, RTMR1 and RTMR2
  must equal the measured row for the replayed `os-image-hash`, and RTMR0 must equal one of
  that row's per-shape values.

Both refusals are `measurement_mismatch`.

`TrustedDstackBootChains` ↔ `trustedDstackBootChains` holds the rows. `TrustedDstackOSImages`
is now derived from it. The measured pairs are:

- 0.5.12 and 0.6.1 on `tdx.small` and `tdx.large`;
- 0.5.9 on `tdx.small`, plus Phala's ACI gateway.

`dstack-nvidia-0.5.12` has no measured row, so **every GPU node is refused**, and so is a node
on any unmeasured instance size.

`DstackVerifier.TrustedBootChains` ↔ `trustedBootChains` takes a caller's table: absent means
the built-in one, and empty refuses everything. An image added to a host's OS-image list
without a row is refused.

### 2026-10-22 — a Solana ticket holds its pending claim (0.10.0)

The `zs_escrow` program's `Ticket` account stores the first half's claim fields
(`Ticket.Pending` ↔ `pending`, a `ClaimFields`) where it stored their hash and the claimed amount,
as Algorand's ticket box keeps `pendingAmount`, `pendingDigest` and the rest. The account grows
from 233 to 275 bytes (`TicketSize` ↔ `TICKET_SIZE`), so a ticket's rent rises from 2,512,560
to 2,804,880 lamports. `settle_lapsed` pays the stored claim and takes no arguments
(`SettleLapsed(e)` ↔ `settleLapsed(e)`). `protest` takes no claim fields and checks the receipt's
digest against the stored one (`Protest` ↔ `protest` lose their `pending` argument).
`judgeSolanaClaim` ↔ `judgeSolanaClaim` compares the receipt's fields with the stored ones.
`ClaimHash` ↔ `claimHash` remains for the ack digest. A deployed program and its tickets must be
replaced, since old accounts no longer decode.

### 2026-10-22 — Go's Solana wallet reads a missing account as absent (0.10.0)

`rpc.HTTPClient.GetAccountInfo` reports an account that does not exist as `rpc.ErrNotFound`,
and the Go Solana wallet read that as a failed read, where it means no account. Against a real
RPC a first-time payer's rent pool could never be created, so its first open failed; a ticket
that had closed read as unreadable; and an ack for a payer with no USDC account failed rather
than forfeiting the refund to the treasury. Each read now takes `ErrNotFound` as no account,
as the TS wallet takes `null`. The test clusters answer a missing account with `ErrNotFound`,
as the real client does.

### 2026-10-22 — the Solana handle's ack (0.10.0)

A Solana ticket's handle now acks a verified receipt, through the same decision as Algorand's
(`ackSettle` ↔ `ackSettle`, generalized over what the settle slot decodes to).

- **With the node's `open_seq`** the payer hands the node its ack over the sealed settle-ack
  route: its signature over the receipt's ack digest as `payment_settle`, binding the Config's
  genesis hash. The node submits its settle and pays for it.
- **With no slot, or no relay to carry the ack** (`errNoSettleAckRoute` ↔
  `NoSettleAckRouteError`), the payer sends its own `ack` transaction over the ticket account it
  read, as Algorand's standalone settle, and pays its 5,000-lamport fee. As on Algorand, a claim
  above the receipt is acked to freeze it, and one that contradicts the receipt without taking
  more is not acked. On Algorand no route still broadcasts the node's group.
- **After a failed delivery** the payer reads the ticket on a fresh budget and sends its ack
  only over a claim above the receipt or an open ticket, as on Algorand; the Solana program
  always has `resolve_frozen`.
- **A payer settle that was sent and failed** reports its transaction id and the fee it paid
  (`AckResult.TxID` / `FeeMicroalgos` ↔ `txid` / `feeMicroalgos`, and the turn's
  `Settlement`), since a Solana transaction that lands and fails pays its fee. An Algorand
  settle that fails has sent nothing, so its report is unchanged. TS: a port that sent its
  transaction throws `SentSettleError` (`SolanaAckSendError` is one), carrying the submission.
- `SolanaWalletConfig.Logger` ↔ `SolanaWalletOptions.log`.

### 2026-10-22 — the payer's own ack on Solana (0.10.0)

The Solana wallet can send the payer's half of a settle itself, the Solana form of
Algorand's standalone settle. Nothing calls it yet; the Solana handle's `AckSettle` is next.

- **`readTicket`** reads the ticket account for a ticket at a node, `nil` ↔ `null` when there is
  none or the program doesn't own the account.
- **`sendAck`** signs and sends the program's `ack` with the payer as sole signer and fee payer,
  and waits for it to confirm. It refuses a ticket whose payer isn't the wallet's before
  asking the signer. A payer whose USDC account can't take a refund (missing, frozen,
  uninitialized, another mint or owner, not the token program's) passes the Config's treasury
  account writable, so the refund is forfeited there as on Algorand; otherwise it passes none.
  A transaction that landed and failed reports its 5,000-lamport fee and the program's
  `TransactionError` beside the error (TS: `SolanaAckSendError.feeLamports` / `.txErr`); one
  that never confirmed reports its signature, with `rpc.ErrExpired` ↔ a
  `TransactionExpiredError` cause once it never can land.
- TS: `solanaClaimFields` moves to `sdk/src/solana/claim.ts`, shared by `judgeSolanaClaim`
  and the ack.

### 2026-10-22 — the claim verdict on a Solana ticket (0.10.0)

The Solana ticket account now maps onto the rail-neutral settlement view, and the payer can
judge an operator's claim on it against its own receipt. Nothing calls either yet; the
Solana ack is next.

- **`zsescrow.(*Ticket).View` / `zsescrow.Classify`** ↔ `ticketView` / `classify`
  (`@txnlab/zs-proto/solana/zsescrow`), the Solana twins of the `escrow` package's. A status
  the decoder doesn't know reads as unrecognized, and a deadline before the epoch as the
  epoch. `ticketDeadline` now takes just `expiresAt` and `grace`.
- **`judgeSolanaClaim`** (Go, unexported) ↔ `judgeSolanaClaim` (`sdk/src/reconcile.ts`,
  exported beside `judgeClaim`, with the `SolanaTicketView` type of the account fields it
  reads) gives the same verdicts as `judgeClaim`. The account keeps the first half's hash
  rather than its fields, so a claim agrees when the receipt's fields hash to it, and the
  pending amount alone decides an over-claim. TS args that can't be hashed (a digest that
  isn't 32 bytes, a count past u64) contradict the claim, as `judgeClaim` finds of them.

### 2026-10-22 — the Solana wallet's open (0.10.0)

Both SDKs can open a ticket on Solana: `zs.SolanaWallet` ↔ `SolanaWallet`
(`sdk/src/solana/wallet.ts`, not in the package's exports). No host builds one yet, since the
Solana rail can't be configured.

- **Building.** `NewSolanaWallet` ↔ `SolanaWallet.create` read the program's Config for the
  mint's decimals, and refuse a Config that is missing or names another mint than the
  deployment's.
- **The open.** `OpenForNode` ↔ `openForNode` check the node's offer against the ticket, the
  node's registered signing key and the Config (`CompleteOpenOffer` ↔ `completeOpenOffer`),
  top up the rent pool first (`SolanaRentPool`), and sign. Nothing is submitted: the handle
  carries `payment_open` as `OpenGroup` ↔ `openGroup` and `payment_ref` as `AppCallTxID` ↔
  `appCallTxId`, for the node to submit. A pool the payer can't fund serves while it has a
  free slot, as on Algorand.
- **What it refuses.** A node below 9.13, which can't read `payment_open`; `Open` ↔ `open`,
  which dispatch calls only for a node that doesn't submit opens; and a second open for a
  ticket it has already signed one for, which SPEC § 3a now states. It remembers signed
  tickets in memory until ten minutes past their `expires_at`.
- **Settling.** A Solana handle's ack, protest, refund and lapse fail with "on Solana is not
  supported yet", and the refund watchdog in either SDK leaves the handle untracked.
- **`RentDepositBelowTargetError`** extends `BelowTargetError`, Go's
  `ErrRentDepositBelowTarget`. `BelowTargetError.name` is now typed `string`, not its literal.

### 2026-10-22 — the Solana payer chooses the ticket id (0.10.0)

SPEC § 3a "The open and the ack on Solana" closes the precondition the entry below left open:
the payer must never sign two opens with one ticket id at a node. On Solana the payer now
chooses the id.

- The reserve request gains `ticket_id` (`ReserveRequest.TicketID` ↔ `ReserveRequest.ticket_id`),
  unsigned, inside the sealed body. A Solana payer's reserve client sends a fresh random 16-byte
  id on every reserve and refuses a ticket naming any other id (`validateTicketShape` ↔
  `checkTicketTerms`). An Algorand payer sends none, and clears one a caller set. A Solana node
  issues exactly that id, or refuses the reserve with `409 ticket_id_taken`; no Solana node
  exists yet.
- The reserve's `presigned_open_txn` and the settle slot are checked by rail (`go/zs/rail.go` ↔
  `sdk/src/rail.ts`). On Algorand they still decode as the open and settle groups. On Solana the
  offer must decode as a transaction, and the slot as an `open_seq`; anything else fails the
  reserve, or sends the ack standalone, as a malformed group does on Algorand. The rail comes
  from `HTTPReserveClient.Rail` ↔ `HttpReserveClientOptions.rail` and the client's deployment,
  and only Algorand is reachable until the Solana rail can be configured.

### 2026-10-22 — the Solana open and ack on the wire (0.10.0)

SPEC § 3a "The open and the ack on Solana" defines what the rail-neutral fields carry on
Solana, and `solana/zsescrow` (`wire.go` ↔ `wire.ts`) writes and reads each value. Nothing
calls them yet: the Solana wallet and the node are still to come.

- `presigned_open_txn` is the node's offer as a base64 wire transaction (`DecodeOpenOffer` ↔
  `decodeOpenOffer`). `payment_open` is the payer-signed offer in base64, and `payment_ref` its
  first signature, the node's, in base58 (`EncodeOpenPayment` / `DecodeOpenPayment` ↔
  `encodeOpenPayment` / `decodeOpenPayment`). The node's reading refuses a `payment_ref` that is
  not the first signature, and a transaction whose signatures don't all verify.
- The settle-group slot carries the ticket's `open_seq` in decimal (`FormatOpenSeq` /
  `ParseOpenSeq` ↔ `formatOpenSeq` / `parseOpenSeq`).
- `payment_settle` is the payer's signature over `ReceiptAckDigest`, in base64
  (`SignReceiptAck` / `DecodeAckSignature` ↔ `signReceiptAck` / `decodeAckSignature`).
  `SignReceiptAck` refuses a signature that doesn't verify as the payer before it reaches the
  node. It signs whatever `open_seq` it is handed, the node's: a caller must first refuse any
  open offer whose ticket id the payer has already opened at that node (SPEC), which neither
  SDK does yet.
- `EncodeOpenPayment` refuses a completed open whose signatures don't all verify, the node's
  included, which `CompleteOpenOffer` does not check.
- Each value has one spelling, and the readers refuse any other: standard padded base64 with
  no whitespace and zero padding bits, and a decimal with no sign or leading zero (`0`
  excepted). Pinned by the new `solana_wire_vectors.json`.

### 2026-10-22 — funding the Solana rent pool (0.9.2)

Both SDKs can top up a payer's Solana rent pool, the program's form of Algorand's prepaid MBR
pool. No host calls it yet: the Solana wallet that will is still to come, and the TS side is
internal to the SDK (`sdk/src/solana` is not in the package's exports).

- **Sizing.** `planRentDeposit` (Go, unexported) ↔ `planRentDeposit` (`sdk/src/solana/rent.ts`)
  size a top-up by Algorand's rule, through a shared core, `planPoolDeposit` ↔
  `planPoolDeposit` (`sdk/src/pool.ts`, not re-exported), with one ticket's rent as the slot
  and no quota term. The pool's gross is
  its lamports above its own rent plus `open_tickets` × the ticket rent. A deposit costs the
  wallet its 5,000-lamport fee and, on a first deposit, the pool's own rent; the wallet's
  spendable lamports are its balance above the 890,880-lamport reserve. Pinned by the new
  `rent_deposit_plan_vectors.json`; `deposit_plan_vectors.json` is unchanged.
- **The top-up.** `zs.SolanaRentPool` ↔ `SolanaRentPool` read the rents
  (`getMinimumBalanceForRentExemption`, new in both RPC clients), the pool and the balance at
  `confirmed`, send `deposit_rent` signed and paid by the payer, and wait for it to confirm.
  The outcomes are Algorand's: nothing sent for a covered pool, a below-target deposit
  reported beside its signature, and an unaffordable one refused before signing.
  `ErrRentDepositUnaffordable` / `ErrRentDepositBelowTarget` match `ErrDepositUnaffordable` /
  `ErrDepositBelowTarget` under `errors.Is`, and `RentDepositUnaffordableError` extends
  `MbrDepositUnaffordableError`, so the SDK's existing `instanceof` branches take them. Its
  `name` is its own, so a host that matches the Algorand error by name (the chat app does,
  for a second copy of the module) must add it. A deposit sent but not confirmed reports its
  signature: beside the error in Go, as `RentDepositUnconfirmedError.signature` in TS.
- **`getMinimumBalanceForRentExemption`** is a new method on the `rpc.Client` interface ↔
  `SolanaRpc`, so a host's own implementation of either must add it.
- **Confirming a transaction.** `rpc.Confirm` ↔ `confirmSignature` (`sdk/src/solana/confirm.ts`)
  wait for a signature to reach a commitment: through the `signatureSubscribe` watch when
  given one, polling `getSignatureStatuses` otherwise, once it drops, or when its subscribe
  isn't answered within one height check. A transaction counts
  as expired (`rpc.ErrExpired` ↔ `TransactionExpiredError`) only when it has no status after
  the confirmed block height passes its blockhash's `lastValidBlockHeight`, read once more
  past that height.

### 2026-10-21 — Solana ticket rent from the payer's pool (0.9.2)

The `zs_escrow` program takes each Ticket's rent from a per-payer `RentPool`, as Algorand's
`open()` draws box MBR from the payer's prepaid pool, instead of from the node's signer
(SPEC "Settlement asset model", "Ticket rent on Solana"). `solana/zsescrow` follows it:

- **The pool.** `Deployment.RentPool(payer)` ↔ `rentPool(payer)`, the address seeded
  `["rent", payer]`; `DecodeRentPool` ↔ `decodeRentPool` over the 82-byte account (`version`,
  `bump`, `open_tickets`, `payer`); and the builders `DepositRent`, `WithdrawRent`,
  `CloseRentPool` ↔ `depositRent`, `withdrawRent`, `closeRentPool`, the program's forms of
  Algorand's `depositMbr`, `withdrawMbr` and `closeDeposit`.
- **Open names the payer's pool**, writable, after the ticket. `VerifyOpenOffer` ↔
  `verifyOpenOffer` rebuild open with it, so an offer drawing on another payer's pool is
  refused at `open.accounts`.
- **A settle passes the ticket's own `rent_payer`**, unchanged: the pool for a ticket opened
  with one, the node's signer for one opened before. Both verifiers already take it from the
  instruction.
- **The signer floor is fees only**, 10,120 lamports (below).

Neither SDK funds a pool yet: no Solana open path exists in either.

### 2026-10-21 — the Solana registry read (0.9.2)

Discovery can read its operators and nodes from the `zs_escrow` program, read-only. Nothing
in either SDK builds it by default: `ResolveNetwork` ↔ `resolveNetwork` still refuse the Solana
rail, and a host opts in by building its own registry over it.

- **The seam.** `ChainOperatorSource` reads the chain through a `ChainReader`
  (`ReadChain`, `ReadDeployment`) ↔ the SDK's `ChainReader` port (`readChain`,
  `readDeployment`), set as `ChainOperatorSource.Chain` ↔ the `chain` option. Unset, it reads
  the Algorand app as before. The probes, routing stores and registry are the same on either
  rail.
- **The signer-funding gate on Solana.** A node's signing key pays the open offer's fees (the
  payer's rent pool pays the Ticket's rent), so the router holds out a node that can't afford
  one open, as it holds out an Algorand node below 5 ALGO.
  `ChainOperatorSource` runs its signer-balance pass over a reader that is a
  `SignerLamportsReader` (`ReadSignerSpendableLamports`) ↔ one with
  `readSignerSpendableLamports`, as `SolanaChainReader` is: every distinct signer read with
  `getBalance` at `confirmed`, eight at a time within the pass's 10 s, a failed read keeping the
  last reading and a never-read signer routing, all as on Algorand. The reading is the
  balance less an upper bound on the signer account's own rent-exempt reserve (890,880
  lamports), and it rides
  `Operator.SignerSpendableLamports` ↔ `signerSpendableLamports` into the new
  `selection.Operator.SignerSpendableLamports` ↔ `signer_spendable_lamports` (omitted when
  unset, so an Algorand descriptor's bytes and the selection vectors are unchanged).
  `SignerUnderfunded` ↔ `signerUnderfunded` hold a node out when either rail's reading is
  below its floor; the Solana floor is `selection.MinSignerSpendableLamports` ↔
  `MIN_SIGNER_SPENDABLE_LAMPORTS`, 10,120 lamports: two 5,000-lamport signatures and the
  program fixtures' 120-lamport priority fee (1,000 micro-lamports per unit on a 120,000-unit
  limit). The reserve prices rent at 6,960 lamports a byte, the ceiling SIMD-0437's steps
  fall from (the program's fixtures already charge 5,080), so it is an upper bound that
  holds out a node a lower rate would admit. Unlike the ALGO floor the floor carries no
  staleness budget. `SignerReadingsUnderfunded` ↔ `signerReadingsUnderfunded` is
  the one two-rail predicate the gates share. `/v1/zs/operators` lists the reading as
  `signer_spendable_lamports`, and the registry's funding log lines name lamports and
  `floor_lamports` for a Solana node. Still Algorand-only: the doctor copies only the
  microAlgo reading, so it would count a Solana node short of lamports as usable (it reads
  only algod today). From 0.11.0 the `no_funded_operator` refusals name the rail's floor (see
  "`no_funded_operator` and the funding remedies name the rail's coin"), and the doctor reads
  Solana and judges its nodes against the lamports floor (see "the doctor reads Solana").
- **The Solana reader.** `zs.SolanaChainReader` ↔ `SolanaChainReader` read the `Operator` and
  `Node` accounts with two confirmed `getProgramAccounts` calls, each filtered on its account
  discriminator, decode them with `solana/zsescrow`, and build the Operator the Algorand read
  builds: owner, signing key and address (base58), base URL under the same rules, staging,
  and the node's metrics, EWMAs and 30-day revenue windows read the way the Algorand ring is.
  An evicted operator's nodes are left out, an unknown operator status and the node status byte
  are not read, `NFDAppID` is 0, and an account that won't decode (a later program's version)
  fails the read as a malformed box does, all as on Algorand. An account the program does not
  own, which only a faulty RPC returns, is skipped and logged. `SolanaChainReader.OperatorIDs`
  restricts the read, and an empty program is `NoOperatorsError`, as on Algorand. The
  deployment id is `SolanaDeploymentID(getGenesisHash, program id)`.
- **TS options.** `ChainOperatorSourceOptions` is now a union: `algod` and `escrowAppId`, or
  `chain`. An Algorand host's options type-check as before.
- **`zsescrow.AccountDiscriminator`** (Go) is new, for the filter; the TS side already exported
  `discriminator`. The TS `NoOperatorsError` constructor also takes a string naming the escrow.

The new `testdata/solana_registry_vectors.json` (Go's `TestSolanaRegistryVectors`) pins the read
across languages: the program's own Operator and Node fixtures, and edits of them re-encoded in
Go, as `getProgramAccounts` answers, to the Operators built (in `operator_vectors.json`'s
`chain_nodes` shape), the accounts left out and why, the params each read sends, and the
deployment id. Its `signer_balance` block pins the balance pass: passes of one source over
funded, exactly-at-floor, one-below, below-reserve and unreadable balances, a signer two nodes
share, the `getBalance` params each pass sends, each node's reading and whether the selection
rule holds it out, and the floor and reserve as literals.

### 2026-10-21 — the payer's Solana transaction signer (0.9.2)

The Solana rail gets its transaction half of the signer port, in the shape of Algorand's: the
port signs whatever message it is handed, and the verifier gate sits one layer up, in functions
that take a counterparty's transaction, check it, and only then sign. Nothing in the SDKs calls
them yet; their Solana rail will.

- **The port.** Go's `solana.TransactionSigner` (`SignTransactionMessage(ctx, address,
  message)`) ↔ TS's `TransactionSigner` in `@txnlab/zs-proto/solana`
  (`signTransactionMessage(address, message)`): raw Ed25519 over a transaction's message bytes,
  returning the 64-byte signature. It is the same primitive as `signBytes`, kept a separate
  method so a host can route the two to different custody paths. `zs.SolanaSigner` ↔ the SDK's
  `SolanaSigner` pair it with `PayerSigner`. `keystore.SolanaKeys` implements it, and
  `SolanaKeys.Signer(addr)` is a `zs.SolanaSigner` that signs as `addr` alone, as the TS
  signer refuses another address; `solanaSigner(key)` in
  `@txnlab/zerosignal/accounts/solana` now returns a `SolanaSigner` rather than a
  `PayerSigner`.
- **Placing the signature.** `Transaction.SignWith` ↔ `signTransactionWith` ask the port for
  one key's signature, check it with the runtime's strict verify, and put it in that key's slot
  among the message's signers, leaving the other slots as given. A key that is not a signer is
  refused before the port is asked, and a signature that is not 64 bytes or does not verify
  under the key (a host signing with the payer's Algorand key, say) is an error, not a slot
  filled. A signature with a small-order R, which `crypto/ed25519` and @noble's own verify
  accept, is refused in both tests.
- **The gate.** `zsescrow.CompleteOpenOffer` / `CompleteRelayedAck` ↔ `completeOpenOffer` /
  `completeRelayedAck` take a node's open offer or a relayer's ack as a wire transaction, run
  `VerifyOpenOffer` / `VerifyRelayedAck` on its message, and only then sign it as the spec's
  payer, returning the transaction with the payer's slot filled; nothing is submitted. A refusal
  is the verifier's `OfferRejectedError` / `AckRejectedError`, raised before the port is asked.
  An offer that doesn't decode, or a signer that fails, is another error and no evidence against
  the node, as with Algorand's `CompletePresignedOpenGroup`. Signed, verified and returned are
  one message from one parse. A transaction the payer builds itself (a payer-paid ack, a
  protest) has nothing foreign to check and goes through `SignWith` directly.

The new `testdata/solana_sign_vectors.json` (Go's `TestSignVectors`) pins the signed bytes
across languages. The program's `open`, `open_v0`, `open_fold_settle` and `ack_relayed`,
completed with its payer's key, and its payer-built `ack` and `protest`, signed through the
port, come out as the transactions Rust signed. Offers, a relayed ack and a payer-paid ack built
in Go for the chat app's exported phrase and solana-keygen's 12- and 24-word phrases are signed
through `keystore.SolanaKeys`. The SDK reproduces them by deriving each key from its phrase with
`solanaKeyFromPhrase` and signing through `solanaSigner`. Both suites also run every case of
`solana_open_offer_vectors.json` and `solana_ack_vectors.json` through the complete functions,
which must refuse with the case's field slug before the signer is asked, and sign an accepted one
exactly once, as its payer, over the message given.

### 2026-10-21 — a Solana RPC client and its retry policy (0.9.2)

Go's new `solana/rpc` and the TS SDK's `sdk/src/solana/rpc.ts` and `pubsub.ts` are a thin
JSON-RPC client for the Solana rail, hand-rolled rather than `solana-go` or `@solana/kit`.
Nothing calls them yet; the SDKs' and the node's Solana rails will. The methods are the ones
those rails read and submit with: `getAccountInfo`, `getProgramAccounts` (with `dataSize` and
base64 `memcmp` filters), `getBalance`, `getLatestBlockhash`, `getBlockHeight`,
`getGenesisHash`, `sendTransaction` (base64, with `skipPreflight`, `preflightCommitment` and
`maxRetries`) and `getSignatureStatuses`, plus `signatureSubscribe` over a WebSocket as the
confirmation watch, since the public endpoints answer `getSignatureStatuses` polling with 429.
Account data comes back as bytes for `solana/zsescrow`'s decoders. Go's client is an interface
(`rpc.Client`) over a pooled HTTP/2 transport; its socket is `golang.org/x/net/websocket`, which
the module already required. TS's socket is the platform's `WebSocket` or one the host passes.

Neither client accepts an endpoint carrying `user:password` (pass credentials in a header), and
no error either one returns spells the endpoint, since a provider's API key often rides in its
query. Go's socket takes a header, TLS config and dialer (`PubSubOptions`) and never an HTTP
proxy. Nothing in either notices an upstream that holds the socket open and stops sending, so
the caller bounds each watch, by the blockhash's `lastValidBlockHeight` or a timer. A write that
fails ends the socket as a drop does: every watch ends with `ErrPubSubClosed` ↔
`PubSubClosedError`, later subscribes are refused with it, and the caller redials. In Go that
includes a write past its 10 s deadline to a peer that stopped reading. A platform `WebSocket`
never fails a send to such a peer (the frame waits in `bufferedAmount`), so in TS only a
host-passed socket whose `send` throws ends this way.

An account answer whose `lamports`, `owner` or `data` is missing, null or of another JSON type,
or whose `executable` is null or not a boolean, is a malformed answer in both, never read as its
zero value; a missing `executable` reads as false. A `getAccountInfo` answer with no `value` is
malformed too, and only a null one is an account that does not exist.

Every call retries a transport failure, a 429 and any 5xx, as algod's transport does, and two
JSON-RPC answers that are weather: `-32005` (node behind) and, on `sendTransaction` only, a
`-32002` simulation failure whose error is `BlockhashNotFound`. Every other JSON-RPC error is returned at once, a simulation's
`AlreadyProcessed` or `InsufficientFundsForFee` included; `Error.TxErrName` ↔ `txErrName` names
its `TransactionError`. The budget is 8 retries after the first attempt, waiting 0.5 s more each
time up to 10 s (18 s in all), or a longer `Retry-After` up to the same cap. The wait is
algod's, so Go's Retry-After parse moved to `httpx.LinearBackoff` / `httpx.RetryAfter`,
unchanged, and the TS twin calls `algodBackoffMs`. The new `testdata/solana_rpc_vectors.json`
(Go's `TestSolanaRPCVectors`) pins the budget, which outcomes retry, the wait before each retry,
how a `TransactionError`'s variant is read, the params each method sends, and what
`getAccountInfo`, `getProgramAccounts` and `getSignatureStatuses` read from an answer or refuse.

### 2026-10-21 — the payer's check of a relayed Solana ack, and its ack digest for a receipt (0.9.2)

`@txnlab/zs-proto/solana/zsescrow` and Go's `solana/zsescrow` add the payer's two ways to ack a
`zs_escrow` ticket's claim. Nothing calls them yet; the SDKs' Solana rail will.

`VerifyRelayedAck` ↔ `verifyRelayedAck` checks an `ack` transaction that a relayer (the node, or
anyone paying the fee for a payer that holds no SOL) built, before the payer signs it. The
program counts the payer's signature on a transaction as its ack of every `settle_cooperative`
of the payer's tickets in it, so the check accepts the `ack` alone: any fee payer, the payer as
the read-only second signer, compute budget leading as in the open offer, then exactly one
`ack`, which must post the payer's half of its own ticket at exactly its receipt's claim, the
receipt naming that ticket. It refuses an address lookup table, a third signer, a write lock on
the payer's wallet, any program but the compute budget and the escrow, any other escrow
instruction (a `settle_cooperative` or a `claim` beside the ack), a second ack, and an ack for
another ticket, another node or another claim. A refusal is an `AckRejectedError` whose `field`
slug matches `OfferRejectedError`'s where the check is the same.

`ReceiptAckDigest` ↔ `receiptAckDigest` is the off-chain ack: the program's settle-ack digest
(`AckDigest` ↔ `ackDigest`, unchanged) over the claim hash of the receipt's claim, refused with
`ack.receipt` unless the receipt names the payer's ticket. The caller passes the ticket
account's `open_seq`.

The open offer's verifier now shares its message checks with the ack's; its verdicts are
unchanged, and `solana_open_offer_vectors.json` gains one case, an `open` with an account past
its last. The new `testdata/solana_ack_vectors.json` (Go's `TestAckVectors`) pins both for the
two languages, over the program's own ack transactions and acks built in Go. Each of the
program's acks claims a real receipt, which its fixture records and the vectors' spec carries,
so the program's `ack_relayed` is accepted as it ran. `ack_extra_settle` is refused as
`escrow.instruction` because of the `settle_cooperative` beside its ack; the ack alone is
accepted (`extra_settle_ack_alone`). The payer-paid `ack`,
`ack_first_half` and `ack_mismatch` are refused as `header.signers`: they have one signer, and
a payer that builds its own ack has no relayer's transaction to check.

### 2026-10-21 — the payer refuses a receipt for another ticket and bars its node (0.9.2)

Both SDKs' receipt check (`zs.VerifyReceipt`, `verifyReceipt`) now refuses a receipt whose
`ticket_id` is not the ticket the payer opened, by the rule in [`SPEC.md` §3a "Settlement
receipt"](./SPEC.md). The receipt's id must be the canonical padded standard base64 of the
ticket's 16 bytes, and so must the ticket's own id; the comparison is on the string, as the
Solana open offer's fold compares. An honest node always echoes the ticket's id, so only a
misbehaving node is refused.

The refusal is a `sig` violation: `ReceiptViolated` with violation `sig`, the spend guard's
reservation released, no protest, no settle, and the receipt's figures neither pinned on the
refund watchdog nor journaled as `Signed` / `signed`. Before this, such a receipt that matched
the delivered body was acked at its own figure, and one that failed its `body_hash` drove a
protest, which Solana's program refuses (`ReceiptNotForTicket`) and Algorand's would take on an
open ticket, freezing it over a receipt about another ticket.

Unlike the rest of the `sig` path, a receipt whose signature verified but that names another
ticket also bars its node for the rest of the process, as an over-claim does: a `NodeExcluded`
with reason `receipt_names_other_ticket` follows the `ReceiptViolated` on a stream, and a warn
line logs it. A bad signature, a nil receipt or ticket, and a payer ticket id that is not
canonical bar no node, since none shows the node wrote a receipt for another ticket. The
classification is Go's unexported `errReceiptNamesOtherTicket` in the `ReceiptError` chain, and
TS's `ReceiptForAnotherTicketError` as the `ReceiptError`'s cause.

Go's wallet now also refuses to open a ticket whose id is not in that canonical spelling, as
the TS wallet's decoder already did, so it no longer locks an escrow for a turn whose every
receipt it would refuse. The journal and the refund watchdog still decode such an id, so an
escrow an older build opened under one stays refundable.

`testdata/receipt_check_vectors.json` (Go's `TestReceiptCheckVectors`) pins the verdict for
both SDKs, and with each scenario's `exclusion` the reason that verdict bars the node for.
Go's `VerifyReceipt` also refuses a nil `ReceiptCheck.Ticket` now, where it skipped the
deployment and amount checks before.

### 2026-10-20 — the payer freezes an operator claim above its receipt (0.9.0)

The payer now answers an operator's settle claim that it can see on the ticket box, by the
rule in [`SPEC.md` §3a "Payer's check of an operator claim"](./SPEC.md): a claim above a
receipt the node signed is frozen with the payer's settle at the receipt's values, and any
other disagreement is left to lapse.

**Only on a contract that has `resolveFrozen`.** A freeze locks the ticket's escrow until the
admin's `resolveFrozen` decides the split. On a contract without it, a frozen ticket's
escrow is locked for good, so a freeze would cost the payer the whole `max_price`. So the payer checks the deployed approval program for
`resolveFrozen`'s ARC-4 selector when it loads the escrow config (`escrow.Client.ResolvesFrozen`,
`EscrowChainConfig.ResolvesFrozen` / `resolvesFrozen`). Without it the payer sends no freeze:
it does not ack an over-claim, which then lapses at the operator's figure, and it posts no half
of its own after a failed ack. It still never lapses an over-claim itself, and still bars the
node. The check does not cover the payer's first half from a standalone ack on an open or
unreadable box, or the reconciler's resettle on an open box. Those go out as before, so a node
half that lands after one at another figure still freezes the ticket.

- **Ack:** before a standalone ack, and after the node's settle group fails to submit, the
  payer reads the box. An over-claim gets the payer's settle at the receipt, which freezes the
  ticket. Its node is excluded with `NodeExcluded` reason `settle_claim_exceeds_receipt`, and
  the turn's `Settlement.Frozen` / `frozen` and `SettleSubmitted.Frozen` / `frozen` are set
  when the freeze went out. After a failed group submit an `OPEN` box gets the payer's own half
  at the receipt, so a node half posted later at any other value, a lower one included,
  freezes the ticket instead of lapsing. Any other claim leaves the error standing, and
  nothing is sent. The box read and that settle run on a time budget of their own, so an ack
  delivery the node holds open cannot use theirs up. A claim that differs without taking more
  is not acked: the turn's `Settlement` has kind `SettleNone` / `''` and no error.
- **Protest:** a refused `body_hash` protest over an over-claim falls back to the payer's
  settle at the receipt, reported as `SettleProtest` / `'protest'` with that settle's txid,
  `Frozen` set, and a `NodeExcluded` after `ReceiptViolated`. A landed protest also reports
  `Frozen`.
- **Reconciler:** it freezes such a claim inside the window, including on a ticket the refund
  watchdog still drives, and never lapses it. A receipt that failed its `body_hash` or amount
  check after its signature verified is journaled as `TicketRecord.Signed` / `signed` on the
  open row, so the reconciler holds the claim against it too. Every sweep that reads such a
  claim bars the node.
- **Refund watchdog:** it never posts `settleLapsed` for a claim above the receipt it saw, and
  bars the node when it finds one. While it holds a receipt it does not post `settleLapsed`
  after a box read that failed.
- **Fees:** a freeze, and the payer's half on an `OPEN` box, pay for the outer call alone
  (`escrow.SettleArgs.OuterFeeOnly`, `PayerSettleCall.outerFeeOnly`), since neither can
  finalize: the contract's freeze branch and a first half fire no disbursement or op-up. The
  half after a failed ack costs the payer one minimum fee and one algod submit from its IP.

**Consumer-visible.**
- Go's `OpenHandle.AckSettle` returns `(AckResult, error)`, with the claim's `ClaimVerdict`,
  `PayerSettle` and `Frozen` on it.
- `ClaimVerdict` gains `open` (`ClaimOpen`), for an `OPEN` box.
- TS `AckSettleResult` gains optional `claim`, `payerSettle` and `frozen`, and
  `AckSettlePorts` optional `claim()`, `freeze()`, `half()` and `resolvesFrozen()` ports.
  `OpenHandle` gains an optional `freezeOverclaim`. A host's own handle without them behaves as
  before, except that without `freeze()` an over-claim is frozen through `standalone()`, and
  without `resolvesFrozen()` neither a freeze nor the half after a failed group submit is sent.
- TS `ReconcileAction` gains `'freeze'`. A host with an exhaustive switch over reconciler
  actions must handle it. TS `TicketChain` gains `freezes()`.
- `TicketRecord` gains `Signed` / `signed`. A host journal must persist it as it persists
  `Settle` / `settle`. Go's `FileJournal` writes it as `signed` in the same file version. An
  older binary reads such a file, but its next journal write rewrites the whole file without
  `signed` on any row.
- `Settlement` and `SettleSubmitted` gain `Frozen` / `frozen`.

### 2026-10-19 — network fees are reported in the rail's coin (0.9.0)

A payer's network fees now have names that do not assume ALGO, so a Solana rail can report
lamports without filling fields named for µALGO.

- **Headers:** `X-Zs-Fees-Amount` (base units), `X-Zs-Fees-Currency` (`ALGO`, `SOL`),
  `X-Zs-Fees-Decimals` (6, 9) and `X-Zs-Fees-Usd-Rate`. `X-Zs-Fees-Usd` converts by the
  decimals, which for ALGO gives the same figure as before. Each is on the CORS expose list.
- **The `zs.usage` frame:** a `network_fees` object, `{amount, currency, decimals, amount_usd,
  usd_rate}`, after the `algo_*` keys and before `fee`. `amount_usd` and `usd_rate` are left
  out when the rate is unknown.
- **The USD rate is ALGO's.** Nodes report only an ALGO/USD rate in the reserve response, so
  `NativeUSD`, `X-Zs-Fees-Usd-Rate` and `X-Zs-Fees-Usd` are 0 or absent on any other rail
  until a node reports its rail's own rate.
- **Events and records:** `NetworkFees` on `PaymentCommitted`, `SettleSubmitted` and
  `Settlement`. `ReceiptVerified` gains `OpenNetworkFees`, `SettleNetworkFees`, `NativeUSD` and
  `FeeUnit{Currency, Decimals}` (TS `networkFees`, `openNetworkFees`, `settleNetworkFees`,
  `nativeUsd`, `feeUnit`). `FeeUnitOf(rail)` / `feeUnitOf(rail)` gives a rail's unit.

**Consumer-visible.** Every old name is still sent and still populated on Algorand, so a host
reading `X-Zs-Fees-Microalgos`, `algo_fees_microalgos` or `FeesMicroAlgos` sees no change
there. On any other rail those names are absent (headers, frame keys) or 0 (event fields),
never holding another coin's units. They are deprecated and go no earlier than one release
after the Solana rail ships. The new TS fields are required, on the events and on the
`Settlement` record, so a host test fixture that builds one needs them, and `zs.fetch` renders
a `receipt.verified` event from its new fields. The settle log's `fee_microalgos` key is now
`network_fee`. A reader of the frame should read `network_fees` first and fall back to
`algo_*`, since it may be talking to an older proxy.

### 2026-10-19 — dstack 0.5.12 and 0.6.1 guest images are trusted, 0.5.12 is scanned; nvidia-0.5.9 is not trusted (0.7.0)

`attest.TrustedDstackOSImages()` (TS `trustedDstackOSImages`) adds `dstack-0.5.12`,
`dstack-nvidia-0.5.12` and `dstack-0.6.1`, each checked against the vendor release, and drops
`dstack-nvidia-0.5.9`. Phala no longer offers either 0.5.9 image. `dstack-0.5.9` stays because
Phala's ACI gateway still runs it.

**Consumer-visible.** A node on one of the new images now attests. A GPU node still on
`dstack-nvidia-0.5.9` stops attesting, and payers stop routing to it as a TEE node, so redeploy
it on `dstack-nvidia-0.5.12` before bumping a payer pin.

`OSImagesWithoutSSHDaemon()` adds `dstack-0.5.12`, so an ACI upstream that moves from 0.5.9 to
0.5.12 keeps its root-backdoor concession. The scan first verifies the rootfs against the
measured dm-verity root hash, then lists it. `dstack-nvidia-0.5.12` and `dstack-0.6.1` are not
scanned, so an upstream on either gets the strict rule. Re-running the scan on 0.5.9 corrected
the list's godoc: both images' initramfs carry `getty`, `login` and `su`, and both rootfs carry
`su` and `sulogin`. No getty is ever started (no getty unit, no `agetty`, initramfs `/init`
only switches root), and `sulogin` is reachable only from boot-time failures that happen
before `/etc` becomes writable, while root is still locked. The godoc also states two premises
the scan cannot check: the kernel command line is the published one, and the upstream's own
containers are not covered.

**The compose policy reads dstack 0.6 documents.** A Phala `dstack-0.6.1` CVM writes
`manifest_version` as the string `"3"` and adds `init_script`, `key_provider` and
`key_provider_id`. Before this change Go refused such a document as malformed, and TS refused
it on the version. Both now read `manifest_version` the way dstack 0.6 does, and
`ComposePolicy.ManifestVersions` (TS `manifestVersions`) replaces `ManifestVersion`; both shipped
policies accept 2 and 3. The new fields each get a rule:

- `init_script` is a root boot hook like `pre_launch_script`. It is pinned by digest in
  `InitScriptDigests` / `initScriptDigests`, which no shipped policy populates, so any non-empty
  script is refused.
- The key provider must be `kms`, worked out as dstack 0.6 does: `key_provider` when present,
  else from `kms_enabled` and `local_key_provider_enabled`. Comparing only the optional field
  would refuse `"key_provider":"none"` and accept the same keyless deployment written as
  `"kms_enabled":false`.
- `key_provider_id`, when present, must be Phala's KMS (`PhalaKMSKeyProviderIDs` /
  `phalaKMSKeyProviderIds`); the 0.6 guest refuses keys from any other provider. A document
  without the field is accepted, as every 0.5.x one is, so this does not establish which KMS a
  node used. The replayed `key-provider` event records that and is not yet checked.

New violation codes: `init_script`, `key_provider`, `key_provider_id`. TS now refuses a
document whose modelled field has the wrong JSON type, as Go always has, where it used to read
the zero value and could pass what Go refused. `compose_vectors.json` pins the parse and each
rule in both languages, including the document a live `dstack-0.6.1` node published.

**API change.** `ComposePolicy.ManifestVersion int` is now `ManifestVersions []int` (TS
`manifestVersion` → `manifestVersions`). No consumer in this workspace sets it.

### 2026-10-19 — local state is named by deployment, not by app id (0.7.0)

Journal rows, the saved catalog and a host's state files were scoped by the uint64 escrow app id,
which a Solana program id cannot be. Both SDKs now resolve a `Network` to a deployment key,
`<rail>-<network>-<escrow>` such as `algorand-mainnet-3628061142` (Go `zs.ResolveNetwork` →
`Deployment.Key`; TS `resolveNetwork(...).key`), pinned by `deployment_vectors.json`. A preset's
app id takes that preset's name whatever the config named; any other takes the network the
config names, or `custom` when it names only an endpoint. So testnet's app 42 and mainnet's app
42 no longer share a journal, where a mainnet Client would forget the testnet row.

- Journal rows gain `deployment`, and Algorand rows still carry `escrow_app_id`, so an older SDK
  reading the journal finds them. A row without `deployment` belongs to the deployment with its
  app id. The Go file journal stays at version 1.
- `TicketJournal.List` / `list` take the deployment instead of the app id. A host's own journal
  implementation filters with `Deployment.Owns` / `ownsRecord`.
- Go `OpenFileJournal(path, legacy...)` merges and then removes journals under earlier names,
  leaving one another process holds or one that will not read (`FileJournal.MergeSkipped`);
  `Stores.JournalLegacyPaths` passes them through `New`. `Discovery.CatalogLegacyPath` renames
  the saved catalog, and `StateFile(dir, prefix, d)` returns both names. TS
  `catalogStorageKey` takes the resolved network (a `bigint` no longer compiles). A registry the
  SDK builds reads `zs.catalog.<app id>` once when the new key holds nothing; a host building
  its own `DiscoveryRegistry` passes `legacyStorageKey` for the same.
- `Network.Rail` / `rail` exists; a rail other than Algorand is refused with `invalid_config`
  until the Solana rail lands.

Going back to an SDK before this release, rename the files back: their contents still read.

### 2026-10-13 — a no-fit message names the limit the filter failed (0.5.1)

The per-operator lines of a `context_length_exceeded` message recomputed the miss from the
request's v1 input count. The filter charges a 9.2 node the v2 count instead, and passes a 9.11
node's window when the upstream can take the request, so a node that failed only its
`max_output_tokens` cap could be reported as over its context window, with a need it was never
charged. `selection.SizingMiss` now carries the filter's own reading, `input_tokens` and
`context_window_exceeded`, and both SDKs' messages use it. Routing is unchanged.

### 2026-10-13 — `CatalogEngine` and `EphemeralVerifyCache` are gone (0.5.1)

The TS SDK no longer exports `CatalogEngine` (with `CatalogEngineOptions`, `ProbeObservation`,
`CatalogNodeRef` and `CatalogNodeView`) or `EphemeralVerifyCache` (with its options type).
`DiscoveryRegistry` replaced the first when the SDK took over discovery, and nothing used the
second. `restoredProtoVersion`, `checkEphemeralAdvertisement` and `recordEphemeralStaleness`
stay exported from `@txnlab/zerosignal/catalog`.

### 2026-10-13 — the newest tool-call id decides the pin (0.5.1)

A client resends its whole history, so a request carries every earlier tool-call id, and both
SDKs pinned to the node behind the OLDEST one with a live pin. A conversation that moved off its
first node (a `prefer` pin that yielded) therefore snapped back to it while that pin lived,
losing the KV cache and, on Responses, sending the round's reasoning to an account other than the
one that encrypted it. Both SDKs now walk the ids newest first. (A conversation already served by
two accounts still replays earlier rounds' reasoning from both; this does not change that.) A newest id whose node is gone or excluded is still no preference; an
older id is not consulted past it.

### 2026-10-13 — Go reads the `provider` routing key exactly (0.5.1)

Go's `ExtractRoutingPreferences` matched the top-level key case-insensitively, so a body carrying
`"Provider"` set routing preferences in Go but not in TS, and Go's `DropRoutingPreferences`
(exact key) left it in the sealed body. Go now reads `provider` exactly, as TS and the drop do.

### 2026-10-13 — a Responses tool turn returns to the node that issued the call (0.5.1)

The tool-call pin read only chat shapes (`messages[].tool_call_id`, `tool_calls[].id`), so a
`/v1/responses` tool turn was routed from scratch and could land on another node. For a stateless
client (`store: false`, such as Codex) that turn replays the earlier reasoning items'
`encrypted_content`, which an upstream encrypts under its own account and refuses from any other
(OpenAI answers an organization mismatch). Both SDKs now record the `call_id` of every Responses
`output[]` item and streamed `item`, and pin a request by the `call_id` of its `input[]` items,
under the same `affinity_policy` as chat.

### 2026-10-13 — the tool-call pin passes the TEE gate (0.5.1)

A tool-calling turn is pinned to the node that issued its `tool_call_id`, and `SelectTargets`
put that node first without checking, for a request requiring TEE, its attestation. So a
confidential tool loop whose node lost its attestation between turns sent the tool results back
to it. Both languages now check it on the pinned node: under `prefer` the pin yields to the other
candidates, and under `strict` selection reports `tee_blocked`, as the `previous_response_id`
pin already did. The wire version stays unchecked there on purpose, since
`selectTargetsForOperator` relies on it to still try the payer's own pick. Pinned by new
`selection_vectors.json` cases.

### 2026-10-13 — a node's `payer_not_opted_in` refusal makes the wallet check the MBR deposit again (0.5.1)

Once the wallet has seen the payer opted into the escrow app with its MBR deposit covering the
working set, it skips those reads on later requests. A deposit closed outside the wallet —
`zs-proxy close-deposit` while the daemon runs, or "Close pool" in another browser tab — went
unnoticed, so reserves were refused `payer_not_opted_in` until the process restarted or a request
reached a node whose cache still admitted the payer (its open then reverted, which already
re-deposited). Both SDKs now have the wallet check again when a node refuses with that code (Go:
the optional `DepositRechecker` interface, which `*Wallet` implements; TS: the optional
`WalletOpener.recheckDeposit`), and the next request opts in and deposits again. The refused
request itself still fails, and a node that refused within the last few seconds may refuse once
more from its cache.

### 2026-10-13 — a re-probed node's ticket is checked against the request it answers (0.5.1)

When a reserve hit a stale ephemeral key, both SDKs re-probe the node and re-size the reserve
against what it now advertises, but the price check still read the request as first built. A
node that came back with a different bound version or tool limit signed an honest ticket for the
re-sized request and was refused `ticket_price_rejected`. The check now reads the request the
ticket answers.

### 2026-10-13 — the slot pool counts a part slot (0.5.1)

Funding the prepaid ticket-MBR pool now counts a part slot already in the pool toward the next
one, in both SDKs. Previously the pool and the wallet were each floored to whole slots, so a pool
holding three slots and most of a fourth, beside a wallet that could pay the rest, read as unable
to afford a fourth and asked for a whole one. `need` (Go: the `ErrDepositUnaffordable` message;
TS: `MbrDepositUnaffordableError.need`) is now what the part slot lacks rather than a whole slot.

### 2026-10-13 — a whole reply is bounded, and a caller's leaving reaches a stream before its headers (0.5.1)

Both SDKs now read a whole (non-streamed) reply's body under the stream idle bound's
between-bytes budget, 60 s by default, and refuse one over 256 MiB. Either ends the turn
`read_upstream`, with the `StreamIdleTimeoutError` or the size error as its cause. This covers
the buffered forward and a buffered reply to a streamed request. Previously a node or relay
that stopped sending mid-body, or never ended it, held the turn and its escrow until the caller
gave up. `StreamIdle{Off: true}` (TS `streamIdle: false`) turns off the time bound but not the
size cap.

A caller who cancels a streamed request before the node's headers arrive now ends it at once.
Previously the request ran on until the headers came, or the 5-minute header backstop. The
relay is no longer charged for that request, and the failure is logged at debug rather than
error.

### 2026-10-13 — the Go SDK cuts a silent stream (0.5.1)

A streamed answer whose node or relay stops sending without closing now ends
`stream_interrupted`, its `Err` a `*StreamIdleTimeoutError`, as in TS: by default after 300 s
with no first byte, 60 s between bytes after that, or 300 s while the node runs an image tool.
Previously the Go SDK waited as long as the caller's context allowed, and the turn's escrow
with it. `Config.StreamIdle` sets each bound, and `StreamIdle{Off: true}` turns it off.

### 2026-10-13 — host hooks can't bypass the spend cap or stop the SDK (0.5.1)

A `SpendGuard` method that returns a Promise no longer slips past the cap: the TS methods now
return `SpendGuardResult`, so an async one is a compile error, and an async `admit` or `reserve`
ends the request (`spend_cap_exceeded`, naming the async guard) whatever it resolves to.
Previously it was ignored, so its refusal never reached the request, and its rejection could end
a Node process. A `settle` or `release` that throws (Go: panics) is logged rather than failing
the request, the reconciler sweep or the refund watchdog. The reconciler now carries on past a
row that throws or panics, counting it as a failed attempt, and gives back its journal claim
even when its shutdown step fails; the TS `Client.close` stops the registry and the sweep
whatever the other throws. A source whose `reprobeEphemeral` rejects reads as a node the SDK
can't seal to, as Go's does.

**TS hosts:** a synchronous guard whose method returns `void` or a primitive needs no change.
One that returns an object no longer compiles, e.g. `reserve: (id, p) => this.held.set(id, p)`,
which returns the `Map`; give the arrow a block body.

### 2026-10-12 — the private-target guard judges translated IPv6 (0.5.1)

Go's `httpx.IsPrivateIP` (the `BlockPrivateTargets` dial guard, used by the node's relay, web
read and favicon fetches and by the Go SDK's operator clients) and the TS SDK's `isPrivateAddress` /
`isBlockedOperatorUrl` now refuse an IPv6 address that reaches a private IPv4 address. NAT64
`64:ff9b::/96`, SIIT `::ffff:0:0:0/96` and 6to4 `2002::/16` are judged by the IPv4 address they
carry; `::/96`, local-use NAT64 `64:ff9b:1::/48` and Teredo `2001::/32` are refused whole. On a
DNS64 network a name with a private A record resolved into `64:ff9b::/96` and passed the guard.
A NAT64 under a network-specific prefix is still not recognisable, and a host whose DNS64 uses
the local-use prefix can't reach IPv4-only targets through the guard (SPEC §3f, step 2a).

### 2026-10-12 — payer obligations, the pool opt-in and the doctor (0.5.0)

Both SDKs unless noted:

- **The first request opts the payer into the prepaid pool and funds it before reserving**, so a
  payer that never deposited no longer fails with `payer_not_opted_in`. A node's
  `payer_not_opted_in` is now a payer refusal (kind `funds`), not retried on another node.
- **Nothing after the receipt is used.** The receipt's `body_hash` covers only the frames
  before it (SPEC §5.3), so a content frame after it is dropped. A truncated chat frame that
  names a terminal value ends the stream.
- **A missing price reference loosens only the checks that need it**, rather than every price
  check on the reserve.
- **The TEE verdict and status report the upstream's carve-outs.**
- **K_response and the reply-to identity are wiped after each request.**
- **Go: the algod client reads no proxy variables** (`HTTPS_PROXY`, …) unless `UseEnvProxy` is
  set, as the node client already did.
- **The doctor.** `zs.Diagnose` / `diagnose` report, without signing, what an address needs before
  a request can succeed; the TS package ships it as the `zerosignal doctor` command.
  `escrow.ReadPayerDeposit` simulates as the app account, so it answers for a payer with no ALGO.

### 2026-10-12 — a bounded cycle probes the nodes nothing is known about first (0.5.0)

With a fleet larger than `probe_budget`, a node no refresh had tried and that had never answered
(new on chain, aged out of a restored catalog, or cut off by a cycle's deadline) waited for the
round-robin sweep to reach it: with no demand up to fleet ÷ budget cycles, and longer while
recently requested models held their share. Until then a picker showed it as `probing`. Both
SDKs' probe selection (`probeSelection` ↔ `selectProbeSet`) now take such nodes after those
models' servers, from the sweep cursor on, in whatever share of three quarters of the budget
demand leaves; with a budget of 4 or more the sweep keeps its quarter, and a backlog larger than
that share rotates. A fleet whose demand fills the three quarters waits as before, and a node
with an attempt or an answer on record is unchanged. `probe_set_vectors.json` carries each node's `last_refresh_at_ms` and
`reachable_as_of_ms`; the TS `ProbeNode` gains optional `lastRefreshAt` and `reachableAsOf`.

### 2026-10-12 — a catalog row's reachability, from the SDK (0.5.0)

`@txnlab/zerosignal/catalog` exports `reachabilityOf`, `answeredWithin` and `carryLapsesAt`, so
an app rendering a `DiscoveryRegistry` snapshot reads each node's verdict by the rule the
registry advertises on instead of restating it. `answeredWithin` is now the liveness half of the
registry's own `advertisable`, and a test holds `reachabilityOf(...) === 'ok'` to `advertisable`
on every `registry_cycle_vectors.json` case the staging and signer terms don't decide. Whether a
node has been tried (`probing` or `failing`) is per registry: a registry built anew reads every
node it has not yet tried as `probing`. A window of 0 or less is the default, as the registry
reads its setting. TS only: Go's proxy has no picker.

### 2026-10-12 — a saved catalog is loaded under the probe's rules (0.5.0)

Two gaps when a payer starts from its saved catalog, in both SDKs:

- **A boot whose chain read failed seeded the file as written.** A node past the carry window
  kept its models, and dispatch, which applies no carry window of its own, could pick it until a chain
  read succeeded. The seed now goes through the carry window as a cycle would: past it, a node
  keeps its identity (it stays in the relay pool) and serves nothing. A boot whose chain read
  succeeds already merged under the window, and still does.
- **A retention tier the build does not recognise was loaded as saved.** The probe drops such a
  tier, but a file written by a newer build, or edited by hand, put it back on the operator
  until the node's next successful probe. Loading now drops it too.

`registry_cycle_vectors.json` gains a `seed` block, and `persisted_catalog_vectors.json` a load
case with an unknown tier.

### 2026-10-12 — the registry remembers its last probe attempt across cycles (0.5.0)

`Operator.LastRefreshAt` (TS `lastRefreshAt`) used to be set only on a cycle that probed the
node, so on every cycle a bounded probe set skipped it, it was zero again, and a node known to be
failing looked the same as one never tried. Both registries now carry it from the last snapshot
onto a node this cycle did not try, beyond the carry window as well as inside it, since it
records what this process tried and not what the node serves. It is still not saved with the
catalog. `registry_cycle_vectors.json` carries `last_refresh_at_ms` on every operator.

### 2026-10-12 — no evidence fetch for a node with no verified ephemeral key (0.5.0)

Both SDKs' attestation probe used to fetch and verify a node's evidence even when its ephemeral
key had not been taken this cycle (absent, expired, unparseable or badly signed). The verifier
then refused it at SPEC §3e step 0 as `key_binding_mismatch`, which reads as the node attesting
the wrong key, and the fetch cost a request, a relayed one in privacy mode. The probe now fetches
nothing for such a node and reports `ephemeral_unavailable`, a new tag (`tee.FailureEphemeralUnavailable`,
TS `FailureTag.EphemeralUnavailable`) that, like `fetch_failed`, comes from the prober and not
the verifier. Routing is unchanged: the node was unattested before and still is. The verifier
still refuses an empty key at step 0. The tag is neither a verdict on the evidence nor the
payer's own outage, as `fetch_failed` is: it says the node had no usable sealing key this cycle,
which is a fact about the node (or a relay that altered its advertisement). A host that sorts
tags should give it a reason of its own. An operator who reads `key_binding_mismatch` as the sign
of a wrong `node_id` now sees `ephemeral_unavailable` instead.

### 2026-10-12 — the TS SDK lists its catalog on `/v1/models` (0.5.0)

`zs.fetch` answers `GET` and `HEAD` on `/v1/models` and `/v1/models/{id}`, with `/models` and
`/models/{id}` as aliases, as Go's handler does, so `openai.models.list()` works on it. Both read
the same aggregates as Go: the models of every node the registry would route to, each listed
with the lowest rates any of them declared, grossed up by the protocol fee. While the fee is
unread, or when either rate is 0, an entry carries no `pricing`. `testdata/catalog_aggregate_vectors.json`
pins the aggregates and `openai_model_vectors.json` the entries against Go.

- `DiscoveryRegistry.allModelDetails` is new, and `allModels` / `allBuiltinTools` now read the
  same merge rules (`aggregateModels`, `aggregateBuiltinTools`, `aggregateModelDetails`).
- `RegistryProvider` gains optional `allModels` and `allModelDetails`. A registry without
  `allModels` has no catalog, and the routes answer 501 `catalog_unavailable`; without
  `allModelDetails` each model is listed by id alone. A registry read that rejects answers 503,
  which Go never does, since its aggregates cannot fail.
- `@txnlab/zs-proto/inject` exports `openAIModelFromDetails`, `usdPerToken` and
  `huggingFaceRepo`, the twins of Go's `inject.OpenAIModelFromDetails` and its helpers.
- Go: no behavior change. `AllModels`, `AllBuiltinTools` and `AllModelDetails` share one
  implementation between the static and dynamic registries, which the vectors pin.

### 2026-10-11 — the TS SDK's browser fetch refuses private hosts (0.4.1)

Outside Node, `@txnlab/zerosignal`'s default `fetch` was the runtime's own, with no check, and
the SDK never called `operatorUrlAllowed`. With `privacy: 'direct'` a browser payer would probe,
reserve against and send a prompt to an operator whose on-chain URL named `localhost` or a LAN
address, and under `relay_required` it would still use such an operator as a relay. Unless
`allowPrivateHosts` is set, that fetch now refuses a URL whose host `isBlockedOperatorUrl`
blocks, rejecting with a `PrivateTargetError` before the request leaves, as Go's dial guard and
the Node build already did. Such a node stays in the chain read and reads as unreachable.

- The check is a literal-host one, and stricter than Go's: it also refuses `240.0.0.0/4` and all
  of `::/96`, which Go dials. A test holds it to refusing everything Go refuses. A public name
  that resolves to a private address, or a public node that redirects to one, still gets
  through in a browser.
- `PrivateTargetError` is now exported from the package root as well as from
  `@txnlab/zerosignal/node`, and is the same class in both.
- A host that supplies `Config.fetch` is unaffected and owns the check. A browser host on
  localnet sets `allowPrivateHosts`, or, for a `ChainOperatorSource` it builds itself, passes
  its own `fetch`, since `ProbeOptions` has no such setting.

### 2026-10-11 — the TS Client builds its own operator discovery (0.4.0)

`Config.registry` is optional in `@txnlab/zerosignal`. Without it, `Client.create` builds a
`ChainOperatorSource` and a `DiscoveryRegistry` from the resolved `Config`, as `zs.New` does:
the network's algod and escrow app, every `discovery` setting, `storage` for the saved catalog
(under `zs.catalog.<escrow app id>`), `privacy`, `teeVerifier`, `fetch`, `allowStaging`, the
logger and the clock. The Client starts the refresh timer and stops it in `close()`. A registry
passed in `Config.registry` is used as is and never stopped, so a host can share one across
Clients; `buildDiscovery(cfg, chainAlgod(cfg))`, given a resolved `Config`, builds it and the
stores its probes record to as `create` would.

- **Boot.** `Client.create` waits for the saved catalog and one chain read. The first probe of
  every node runs in the background, and the first request waits for it. `zs.New` waits for
  both. `create`'s signal bounds the wait. A boot whose chain read failed doesn't rewrite the
  catalog it just loaded, so an abort isn't held up by that write. A boot fleet with a duplicate or zero node id fails
  `create`, as it fails `zs.New`.
- **One set of routing stores.** With a built registry, every routing store absent from
  `Config.stores` is built, and each one, supplied or built, is the same instance in the probes
  and in dispatch. A relay the probes charge is demoted in the requests' relay choice, and the
  reverse. The built reputation store judges a relay's `relay_upstream_unreachable` claim by the
  probes' last reachability for the target. With `Config.registry` an absent routing store still
  keeps no signal.
- **Retrying algod.** The algod client the TS SDK builds for its wallet and discovery now retries
  as Go's `algod.DefaultTransport` does: a transport failure, a 429 or a 5xx, up to 20 retries
  after the first attempt, waiting 1 s more each time up to 30 s, or a longer `Retry-After`, also
  capped at 30 s. Every method retries, transaction submits included: algod does not apply a
  resent transaction twice, though a submit that landed behind a lost 5xx comes back as an
  "already in ledger" failure, as it does in Go. Each request's timeout and signal still bound
  it, retries included, and the escrow config reads `create` starts now run under its signal and
  10 s bound, as Go's `RefreshConfig` reads run under its context. In a browser a
  cross-origin algod's `Retry-After` is readable only with `Access-Control-Expose-Headers`. `retryingAlgod` builds the same client for a host's own `ChainOperatorSource`.
  `algod_retry_vectors.json` pins the budget, which outcomes retry and each wait against Go.
- `discovery.operatorIds` refuses an id that is not a non-negative integer, or is above
  `Number.MAX_SAFE_INTEGER`, with `invalid_config`. Go's ids are `uint64`; no operator id comes
  near either limit.

### 2026-10-11 — a TEE node is attested only on both measurement checks (0.4.0)

Both SDKs count a node as TEE-attested for routing only when its verdict passed **and** rested
on both reference checks: the guest OS image matched a trusted production image, and the compose
matched a published zs-node release. Before, a pass alone was enough. The verifier's release
match refused an unrecognized compose anyway, so the two usually agreed, but the rule now holds
whatever the verifier is configured to do. Two setups that used to route `Require-TEE` traffic
now get `no_tee_capacity`: a stub pass (`allow_stub`), which carries no checks, and a verifier
with the release match off (`enforce_compose_skeleton: false`) that identifies the workload by a
`trusted_compose_hashes` pin, whose pass has no compose-release check. Both SDKs now log
"operator attestation passed but is not attested for routing" for such a node.

A stub pass now only sets the `verified` display bit. To route `Require-TEE` traffic to a build
that is not a published release, keep the release match on and append that build's skeleton
digest and image reference to `trusted_compose_skeletons` and `trusted_node_images`. The browser
client adds its dev references the same way.

- **Go:** `tee.Verdict.MeasurementChecks` (nil on a refusal and on a stub pass) records the
  checks, `zs.TEEStatus` gains `OSImageChecked` and `ComposeReleaseChecked`, and
  `TEEStatus.Attested()` is the rule `Operator.IsTEEAttested` and the `tee_attested` projection
  read. `/v1/zs/operators` adds `tee.attested` beside `tee.verified`, which stays the pass alone.
- **TypeScript:** `TEEStatus` gains the required `osImageChecked` and `composeReleaseChecked`,
  which `probeAttestation` copies from `verdict.detail.measurementChecks`. A host that builds
  its own `TEEStatus` must set them, or every node reads as unattested.
- A custom verifier (`Config.TEEVerifier` / `Config.teeVerifier`) must report the measurement
  checks, or no node it passes is attested.
- `operator_vectors.json` pins the rule, and `tee_verdict_vectors.json` now pins each verdict's
  measurement checks. The saved catalog never held the TEE verdict, so its format is unchanged.

### 2026-10-10 — the TypeScript SDK verifies TEE evidence itself (0.3.0)

`@txnlab/zerosignal/tee` is the twin of `zs/tee`: `BundleVerifier` and `DstackVerifier` run
Go's checks in Go's order, pinned by `tee_verdict_vectors.json` for a given outcome of the Intel
chain check. `defaultVerifier()` trusts the OS images and zs-node releases in `go/attest`, now
generated into `@txnlab/zs-proto/attest` (`trustedComposeSkeletons`, `trustedNodeImages`,
`trustedDstackOSImages`), and checks the quote against Intel's PCK chain with `@phala/dcap-qvl`
0.6.1, a new runtime dependency loaded on first use. Its collateral comes from Phala's PCCS
mirror by default rather than Intel's PCS, since a browser cannot reach Intel's; `pccs.ts` lists
how its error handling and cache differ from Go's. `fetchAttestation` and `probeAttestation`
port Go's attestation fetch and probe for a host's registry, and `Config.teeVerifier` resolves as
Go's `TEEVerifier` does (`ResolvedConfig.teeVerifier` is new, so a hand-built `ResolvedConfig`
needs it). `TEEStatus` gains a display-only `detail`.

Both SDKs now clamp a bundle's `refresh_seconds` to the evidence ceiling before doubling it. A
cadence that overflowed the nanosecond product could narrow the freshness window to nanoseconds
and refuse the node; any cadence past the ceiling now gets the 80-minute ceiling, as SPEC § 3e
step 2 says.

### 2026-10-09 — the payer's fit filter defers to a 9.11 node

`selection.Fits`, and the reserve-leg `Fits` in both SDKs, go through
`selection.FitsContextWindowFor` (TS `fitsContextWindowFor`). An operator advertising 9.11 or
later (`wire.DefersFitToUpstream`) is offered an input bound up to `CeilingForwardFactor` (3) ×
its input ceiling (`context_window − max_output`), matching the node's forward rule (9.11 below)
minus the node's tolerance, which the payer cannot see. An older operator is filtered on the
window as before. Before this, every payer refused at the window on the bound, which runs about
2× a real tokenizer, so a chat was refused at roughly half the real window whatever the node
would have done. The `previous_response_id` and tool-call pins use the same rule, and a
`context_length_exceeded` from the filter against a 9.11 operator means the 3× cap, not the
window.

### 2026-10-09 — releases are private again

`TxnLab/zerosignal` is private, and new releases follow it. `@txnlab/zs-proto` and
`@txnlab/zerosignal` publish with restricted access and no provenance, so installing either
needs an npm token that reads the `@txnlab` scope. The Go module needs
`GOPRIVATE=github.com/TxnLab/*` and git credentials for the repo. `go/v0.1.0` and `go/v0.1.1`
stay public on the Go module proxy.

### 2026-10-08 — the TypeScript SDK runs a paid turn

`@txnlab/zerosignal` gains `Client`, the twin of the Go SDK's `zs.Client`. `Client.create`
builds the payer from a `Config` with a `registry`; the SDK builds no operator discovery of its
own yet. `stream(request)` routes, reserves, pays, seals and streams one turn and yields its
events in Go's order, with the names and fields `sdk_vocabulary_vectors.json` pins. Its `wait()`
resolves when the escrow submit returns, not when it lands, and `payment.committed` fires when
algod accepts the open group, on both sides. `waitSettles` and `close` drain and stop the
Client. `zs.fetch` (`openAIFetch`) serves the Go handler's POST routes as a fetch function for
an OpenAI client built on `FETCH_BASE_URL`, with the same `X-Zs-*` usage headers, opt-in
`zs.usage` frame and error shapes; the catalog GET routes are not ported. Two behaviours have
no Go counterpart: `Request.admitNode` lets a host refuse a node before anything is sealed to
it, asked again on each sweep and after an ephemeral self-heal; and a streamed answer that
stalls ends with `StreamIdleTimeoutError` (by default 300 s to the first byte, 60 s between
bytes, 300 s while a node-run tool works; `Config.streamIdle: false` turns it off).

### 2026-10-06 — a recovery phrase's separators no longer pick the account

Go's keystore (`DeriveAddress`, `New`) now rejoins a phrase's words with single spaces before
deriving it. A 24-word xHD phrase with a double space, a tab or line breaks between words used
to pass the word-by-word check and then load a different account, because BIP-39 seeds PBKDF2
with the sentence string itself; it now loads the account its words name, the one the client
derives. Funds may sit at the old address, so the keystore also loads the key the phrase's own
spacing derives, logs a warning naming both addresses, and lists only one of them in
`Addresses`: the canonical one, or, for an entry marked `MnemonicEntry.LegacySpacing`, the old
one. A wallet imported between 2026-06-15 and 2026-10-03 stored the phrase as typed and
recorded the old address; it marks its entry so, opens as before and keeps paying as the
address it recorded (`keystore.LegacySpacingAddress`). A key from the environment lists the
canonical address, so a deployment that auto-picks its only key moves to it, while one naming
the old address (a node's signing address) still finds it. A 25-word phrase separated by tabs
or line breaks, refused before, now loads. `@txnlab/zerosignal/accounts/xhd` loads a 24-word
phrase as Go does, or derives the same account from the phrase's 32 bytes of entropy; it
refuses a full-width word that NFKD normalization would turn into a BIP-39 word, as Go's exact
lookup does. `@txnlab/zerosignal/accounts/algosdk` and `/accounts/mnemonic` load a
25-word phrase as Go does, splitting on Go's `unicode.IsSpace` set; `account_vectors.json`
holds Go's outcome, signatures and a signed transaction for each case.

### 2026-10-05 — the ephemeral key verdict is shared

`@txnlab/zerosignal/catalog` gains `checkEphemeralAdvertisement`, a port of the Go SDK's probe
check: after the signature, binding and window checks it refuses a recipient that is not an
age X25519 key (outcome `unparseable`), as Go's `age.ParseX25519Recipient` does, and it flags a
verified block older than the freshness target so the relay that served it can be charged.
A field of the wrong type is `rejected`, as Go's typed decode refuses it; a string expiry
would otherwise sign the same bytes and never expire. `@txnlab/zs-proto`'s `verifyEphemeral`
now reads `ephemeral_sig` as Go's non-strict `base64.StdEncoding` does, skipping CR and LF and
ignoring the unused bits before the padding, so a block Go accepts no longer fails closed in
TypeScript. `ephemeral_verdict_vectors.json` holds Go's verdict on each case. The Go module now
requires `filippo.io/age` v1.3.2, whose bech32 decoder folds ASCII only, matching the build the
vectors were generated with.

### 2026-10-04 — the SDK checks and completes the node's settle group

`@txnlab/zerosignal` gains `completeSettleGroup`: it decodes the node's pre-signed atomic
settle group, runs `verifySettleGroup` (a port of Go's `VerifySettleGroup`, in Go's order),
and only then has the payer sign the ack, returning the group bytes for algod. A refusal is a
`SettleGroupRejectedError` whose `field` matches Go's `Field`; decode and signer failures are
plain errors, so a caller can tell a node contradicting its own receipt from a transport fault.
Go's `VerifySettleGroup` now also refuses a payer ack carrying a note (`payer.note`), a lease
(`payer.lease`), any field outside an app call (`payer.foreignFields`), or an argument past
`settle()`'s twelve (`payer.args`), as the open check does for the transfer; the honest
composer sets none of them. `escrow_group_vectors.json`
(version 2) adds a `settle` section with every per-member guard exercised on both halves.

### 2026-10-04 — the SDK checks and completes the node's open group

`@txnlab/zerosignal` gains `completeOpenGroup`: it decodes the node's pre-signed open group,
runs `verifyOpenGroup` (a check-for-check port of Go's `VerifyOpenGroup`), and only then has
the payer sign the USDC transfer, returning the group bytes for algod. Go's `VerifyOpenGroup`
and `VerifyOpenAppCall` now return an `*OpenGroupRejectedError` whose `Field` names the check
that refused (`payer.rekeyTo`, `open.maxPrice`, …); `Error()` is unchanged. Both sides now
refuse a payer transfer carrying any field outside an asset transfer (`payer.foreignFields`).
The TS group-id check hashes each member in canonical form, as algod does, so an explicitly
encoded zero is judged the same way on both sides. `escrow_group_vectors.json` holds Go's
verdict on a real `ComposeOpenGroup` group and on one variant per guard, and both sides are
tested against it.

### 2026-10-04 — the price verifiers agree at the uint64 edge

- `verifyTicketPrice` (`@txnlab/zs-proto/pricing`) recomputes `max_price` exactly, in bigint,
  and treats a recompute Go cannot represent in uint64 as Go does: skipped under `failOpen`,
  a `max_price` violation (want 0) otherwise. It had compared an inexact float and always
  refused.
- A non-integer count, rate, `min_price`, `max_price`, fee or image-tool budget is refused as
  `max_price` under every policy. It had thrown a `RangeError`. Go cannot hold one, and
  fail-open must not skip it: a budget built from an operator's fractional tool rate would
  otherwise switch the check off.
- Go's `ceil(x/d)` in `pricing` (`CeilInputCost`, and the products behind `ExpectedMaxPrice`)
  and `imageprice` no longer wraps when `x` is within `d` of the uint64 limit. It priced such
  an amount at about 0; TS, in bigint, never wrapped. No real ticket comes near.
- `pricing_vectors.json` (version 4) gains a `verify` section: Go's verdict on 56 tickets,
  covering every check, every boundary and each overflow guard. Both verifiers are tested
  against it.

### 2026-10-04 — a discovery probe rotates past `relay_upstream_unreachable`

`DetailsClient.Fetch` returns a relay's `relay_upstream_unreachable` as a new
`*RelayUpstreamUnreachableError` rather than a plain target-side error, and a 2xx body it
can't read or decode as a `*DetailsBodyError`. The discovery probe now rotates to another
relay on the first, scoring the claim with `RecordRelayUpstreamUnreachable`, and marks the
target down only when every relay that worked said so. A relay that carried a 2xx with a
bad body is credited. The client's probe already did both; SPEC § 3f says so now.
A claim is scored once the probe resolves, not as it arrives: disproved by another relay
in the same probe it counts against the relay, corroborated by another it is credited,
and alone it is judged by the target's last-seen reachability as before.

A relayed probe ended by the caller's cancel, or by its own deadline after the relay
accepted the connection, is a `*RelayHopError` with `CallerAborted` set, and charges the
relay nothing (SPEC § 10); it was recorded unreachable and given a strike. A deadline or
cancel while reading a body is no longer a `*DetailsBodyError`. A cancelled probe leaves
the target's reachability as it was, where it used to mark the target down.

### 2026-10-04 — the TEE verifier is its own package, `zs/tee`

The evidence verifier and the Intel collateral cache moved out of `zs` into
`github.com/TxnLab/zerosignal/go/zs/tee`. Behavior is unchanged; the names moved:

- `zs.TEEVerifier` is `tee.Verifier`. Its `Verify`, and `DstackVerifier.Verify`, take a
  `tee.Node` (operator id, node id, verified ephemeral recipient) in place of a `zs.Operator`;
  `Operator.TEENode()` builds it.
- `zs.DefaultTEEVerifier` is `tee.DefaultVerifier`. `BundleVerifier`, `DstackVerifier`,
  `Verdict`, the `Failure*` and `VerifierID*` tags, `DefaultComposePolicy`,
  `EvidenceMaxAgeCeiling`, `PersistCollateral`, `MeasurementTrusted`, `VerifyTDXQuoteChain*`
  and the collateral errors keep their names under `tee.`.
- `AttestationClient` stays in `zs`: it rides the relay hop, which is `zs`'s.
- New exports: `tee.CollateralTimeout`, and `tee.UseCollateralLogger`, which `zs.New` calls
  with the caller's `Config.Logger`.

`Config.TEEVerifier` keeps its name and its default; only its type is now `tee.Verifier`.

### 2026-10-03 — a `SpendGuard` hears how a ticket ended on chain

`zs.SpendGuard.Settle` and `Release` were called at most once per reserved ticket, from the
request. Now the refund watchdog and the ticket reconciler call them too, from their own
goroutines, once a ticket ends on chain. Both Release on a refund they submitted. The
reconciler also Settles a lapse it submitted, at the operator's claim, and Releases a ticket
whose journaled receipt the request already settled. A call can repeat, can follow an earlier
resolution, and can name a ticket this process never reserved. A guard that adds every
`Settle` to its total now double-counts. Key the reservations by ticket id and count only the
first resolution, as the proxy's guard does.

### 2026-10-03 — one error message no longer names the old project

`tools.ErrUnknownBuiltinTool` now reads "unknown zs builtin tool type" (was "unknown hayai
builtin tool type"). A node returns that text as the message of its `unknown_builtin_tool`
error, so a client sees the new wording once the node takes this release. The code is
unchanged; match on it, never on the message.

### 2026-10-01 — public module and package names

The Go module is now `github.com/TxnLab/zerosignal/go` (was `github.com/TxnLab/hayai-proto/go`)
and the npm package is now `@txnlab/zs-proto` (was `@txnlab/hayai-proto`), published with public
access. Exported identifiers no longer carry the old project name:

| Old | New |
|---|---|
| `tools.IsHayaiBuiltinType` | `tools.IsBuiltinToolType` |
| `tools.FrameToolCallHayai` | `tools.FrameToolCallBuiltin` |
| `tools.StripHayaiCallMarkers` | `tools.StripBuiltinCallMarkers` |
| `selection.ExtractRequestedHayaiTools` | `selection.ExtractRequestedBuiltinTools` |
| `isHayaiBuiltinType` (TS, `inject`) | `isBuiltinToolType` |
| `extractRequestedHayaiTools` (TS, `selection`) | `extractRequestedBuiltinTools` |

**Consumer-visible at build time only.** A consumer must rewrite its import paths (Go) or its
dependency name (npm) and the identifiers above. Nothing on the wire changes and no golden
vector moves.

First public release: **0.1.1** of both — Go `go/v0.1.1` (`go get …/zerosignal/go@v0.1.1`) and
npm `@txnlab/zs-proto@0.1.1`. From here the two release in **lockstep**: every release tags
`go/vX.Y.Z` and `ts/vX.Y.Z` on the same commit, so equal version numbers mean the two
implementations agree byte-for-byte. Under 0.x a minor bump is breaking, a patch is not.
(`go/v0.1.0` exists on the seed commit with the same Go code; it predates the lockstep rule.)

### 2026-09-25 — the root-backdoor carve-out now requires a scanned guest image

`ComposePolicy.AllowedRootBackdoorEnvs` used to be honoured on any guest image. It is now
honoured **only** when the replayed `os-image-hash` is named in the new
`ComposePolicy.RootBackdoorSafeOSImages`, which `ACIUpstreamComposePolicy` populates from
`OSImagesWithoutSSHDaemon()`. An absent or unlisted image drops the concession and the strict
rule fires — fail-closed.

Why it was wrong before: the concession's whole justification is that the image ships no way to
consume an `authorized_keys` file, which is a property of that image and of no other. Waiving
the rule on an image nobody had enumerated waived it on the strength of a different image's
scan. `OSImagesWithoutSSHDaemon()` is deliberately shorter than `TrustedDstackOSImages()` —
trusting an image says its measurement maps to a published artifact; listing it here says
someone opened it and looked. `dstack-nvidia-0.5.9` is trusted and **not** scanned, so the GPU
line gets the strict rule.

**Consumer-visible.** An upstream that verified before may now refuse, and the refusal names the
observed image so the cause is not mistaken for the concession failing to apply. The TS mirror
(`proto/ts/src/attest/compose.ts`) models no concession at all and so owes no change;
`shared_policy.allowed_root_backdoor_envs` in `testdata/compose_vectors.json` stays `[]`.

### 2026-09-24 — a confidential node may advertise the egress built-in tools

`plaintext_terminates` (§ 3e) and `models[].retention` (§ 3c) are scoped explicitly to the
**inference route**: where the node sends the prompt in order to produce an answer. A node
MAY therefore advertise `in_enclave` or `named_upstream` alongside `zs_web_search` /
`zs_web_read` / `zs_image_search` in `builtin_tools[]`, because those run for a request only
when the caller lists the type in `tools[]` (§ 3d).

**Nothing on the wire changed and `ProtoVersion` does not move**, which is exactly why this
belongs here: a verifier holding an allowlisted measurement could previously *infer* "this
posture implies no egress built-ins", because the reference node refused to boot with them
enabled. That inference is no longer sound, and no field signals its loss. Verifier step 7
now states it normatively — `builtin_tools[]` MUST NOT be cross-checked against `posture`,
and a verifier MUST NOT demote on the pair. A consumer that never drew the inference needs no
change.

The image route is unaffected and is still held to the posture: the operator points
`image_llm` somewhere with no caller involvement.

### 2026-09-02 — compose skeletons admit a digest-pinned sidecar

`ExtractComposeSkeleton` / `extractComposeSkeleton` previously refused any
`docker_compose_file` with more than one `image:` line, which made the `sealed_local` rung —
an inference engine running as a second service inside the same measurement — unable to match
a published release at all. Such a node could only ever be verified by a hand-configured
per-deployment hash, which says nothing about *which software* it runs.

A second service is now admitted under two conditions that together make it a pin rather than
an exception:

- **Only the FIRST `image:` is lifted.** Later ones stay in the skeleton as literal text, so
  the release's own engine digest is inside the structure an operator may not vary. Lifting
  the engine instead would mean two references checked against one flat `TrustedNodeImages`
  list, where a released *engine* would pass as a released *node*.
- **A later `image:` MUST be `<repository>@sha256:<64 lowercase hex>`**, else
  `ErrComposeUnpinnedSidecar` / `'unpinned_sidecar'`. `docker_compose_file` is hashed *before*
  environment substitution, so a sidecar written `${ENGINE_IMAGE}` would publish one skeleton
  digest covering every engine the operator later supplies — to the process that sees
  plaintext prompts. This is the same attack `TrustedNodeImages` stops for the first image.

  `${` is refused **anywhere in the reference**, the repository half included. Be precise
  about why, because the obvious reason is wrong for that half: `${REPO}@sha256:<hex>` still
  content-addresses the bytes, so a hostile registry can only serve them or fail. It is
  refused because the rule is spelled `<repository>@sha256:<hex>`, no registry accepts `${`
  in a repository name, and a check that admitted it would leave the sentence above true only
  of the digest half.

Which service is "first" needs no parser: reordering changes the skeleton *and* hands the
release-image check the engine's reference, so a reordered document matches nothing.

`ErrComposeManyImages` / the `'many_images'` `SkeletonErrorCode` are removed; neither had a
caller. Consumers gain a new refusal code and lose one.

---

## 9.13 — signatures bind the escrow deployment (minor)

Ticket, receipt, reserve-request and ephemeral signatures bound only `(operator_id, node_id)`,
and those ids repeat across networks. A signing key registered on two deployments (Algorand
testnet and mainnet today, a Solana deployment next) signed objects valid on both. Each object
now has a deployment-bound layout: a new tag followed by a 32-byte deployment id, `sha256` of
the rail, the network's genesis hash and the escrow id (SPEC §3a "Deployment binding").

- **Tags.** `zs-ticket-v3`, `zs-receipt-v3`, `zs-reserve-v2` and `zs-ephemeral-v2` sit beside
  the old tags, which stay accepted. SPEC §3c now allows a tag added this way in a minor;
  replacing a tag still needs a major.
- **Reserve.** A payer names its deployment (`deployment`) on a reserve to a ≥ 9.13 node, signs
  the bound reserve layout, and requires a ticket bound to that deployment back. The node refuses
  a reserve naming another deployment with `400 deployment_mismatch`, and binds the ticket and
  its receipt when the reserve named its own. A reserve with no `deployment` gets the legacy
  layouts.
- **Details.** A ≥ 9.13 node publishes `ephemeral_sig_v2` and `ephemeral_deployment` beside
  `ephemeral_sig`. A payer that knows its deployment requires the bound signature from a ≥ 9.13
  node. The node also names its deployment in an unsigned `deployment` field, and a payer drops a
  node naming another, or a ≥ 9.13 node naming none, as a failed probe. The TS SDK now reads a
  deployment id's base64 as Go does (CR/LF skipped, unused padding bits ignored) everywhere it
  decodes one, tickets, reserves, receipts and ephemerals included.
- **Gate.** `wire.UsesDeploymentBinding`, failing closed to the legacy layouts. Mixed fleets are
  safe in both directions. No contract change: `settle()` and `protest()` take the receipt digest
  as an opaque argument.
- **Rail-neutral payment names.** A ≥ 9.13 node also reads the payment fields a payer sends under
  names no rail owns: `payment_ref` for the inner header's `algorand_tx_id`, `payment_open` for
  its `open_group`, and `payment_settle` for the settle ack's `settle_group`. A payer uses them
  only with a ≥ 9.13 node (`wire.UsesRailNeutralNames`), since an older one would see no tx id.
  A node refuses a request or ack that names one value under both names, differently. Only the
  JSON keys change: the admission tag and AAD hash the values. The node-to-payer names
  (`presigned_open_txn`, `X-Zs-Settle-Group`, `zs-settle-group`) keep their names until the major
  that drops the legacy layouts, when both ends flip together.

The legacy layouts are refused in a later major, once the fleet advertises ≥ 9.13. Until
then a relay that lowers a node's unsigned `proto_version` can strip the bound ephemeral
signature, and the payer then accepts that node's legacy ticket and receipt too.

## 9.12 — the node submits the open and the settle (minor)

Before 9.12 the payer sent both of a paid turn's transaction groups to algod itself: the
`open()` group before the inference request, and the atomic settle group after the receipt. Both
groups name the payer, so the payer's algod provider (Nodely by default) saw the payer's IP
alongside its address on every turn. A 9.12 payer hands both groups to the serving node, sealed,
and the node submits them. The node also learns from algod's answer to its own submit whether
the open was accepted, instead of polling its pool for a group sent elsewhere.

- **Open.** The inner request frame gains `open_group`, the completed open group (payer-signed
  gtxn[0], the node's own gtxn[1]). The node checks gtxn[1]'s txid against `algorand_tx_id`, runs
  the same app-call check it ran on a pooled open, and only then submits. algod evaluates the
  contract's TEAL on submit, so the answer is the admission signal; the node no longer polls the
  pool for a group the payer sent elsewhere. A rejection is the existing plaintext `402
  payment_verification_failed`, naming only the failure category. A payer that gets that refusal
  after handing the group over re-checks its prepaid-pool deposit before its next open. Pool
  acceptance is still not confirmation, so the open-confirmation watchdog is unchanged.
- **Settle.** New sealed `POST /v1/zs/settle-ack` (`application/vnd.zs-settle-ack+json`). It
  carries the payer-signed settle group and is added to the relay allow-list. The node submits
  the group if it is the one it composed for the ticket. It also accepts the group after its
  driver's standalone claim, because a matching same-side re-claim is a no-op on chain. On a
  stream the node writes its ledger row before the receipt frame, since the payer acks as soon
  as it reads that frame. The
  payer never broadcasts after a failed ack; the ticket finishes on the driver's path. A missing
  route is the one exception: when privacy mode finds no ≥ 9.12 relay, the payer broadcasts the
  group itself rather than sending the ack directly from its own IP.
- **Gates.** `wire.SubmitsOpen` and `wire.TakesSettleAck`, both failing closed. Against a
  pre-9.12 node the payer submits both groups itself, as before, and a 9.12 node still accepts a
  frame with no `open_group`. Mixed fleets are safe in both directions.

This removes the payer's transaction submissions from a turn, not every per-turn link at its
algod provider. The payer still reads its tickets from algod: the settle confirmation poll after
each acked turn, and the reconciler's box sweep. A ticket box or settle txid resolves to the
payer address, so the provider can still tie the payer's IP to the payer through those reads.
SPEC §3a "Residual payer contact with algod" lists them all; closing them needs the ticket reads
routed away from the payer's IP too.

---

## 9.11 — the upstream decides context fit (minor)

A node no longer refuses a prompt as too long as soon as its input-token bound passes the
budget. The bound prices the reserve and runs about 2× a real tokenizer on prose. Using it as a
fit verdict refused honest chats at about 44% of a 160K window (32K output reserve, default 10%
tolerance), before any client compaction could trigger.

When the reserve is already at the model's ceiling (`context_window − max_output_count`), a 9.11
node forwards a body over budget while its bound stays within `tokenize.CeilingForwardFactor`
(3) × the budget, and lets the upstream's tokenizer decide. Above that it refuses
`context_length_exceeded`. The factor bounds the operator's exposure when its declared window is
smaller than the backend's real one. Pricing is unchanged: the reserve is still clamped, so
escrow is the same. An upstream too-long rejection is normalized to `context_length_exceeded`
and is zero-cost on a plain request. Under enforcement, a request forwarded at the ceiling is not
offered the node's built-in tools; the caller's own function tools pass through.

One refund changes: a non-streaming tool-loop request the upstream rejects after completed
rounds now bills those rounds' reported usage, as the streaming loop already did. It used to
settle at zero, which gave a prompt built to overflow on round two its first round free.

Callers ask `wire.DefersFitToUpstream(proto_version)` and compare against
`CeilingForwardFactor` (mirrored in TS as `CEILING_FORWARD_FACTOR`). The payer's pre-reserve
filter applies them (see "the payer's fit filter defers to a 9.11 node" under Unversioned); in
the release that introduced this generation it still refused at the window, so no payer,
the web client included, reached the node's forwarding path. Mixed versions are safe in both
directions: a pre-9.11 operator is filtered on the window exactly as before, and a caller that
predicts the old refusal against a 9.11 node only compacts early.

---

## 9.10 — the posture is bound into `report_data` (minor, but BREAKING for `dstack-tdx`)

The bundle's `posture` block was a self-report bound to nothing, and verifiers checked it only
for internal coherence. So nothing tied the upstream a payer was shown to the upstream the
node actually sends prompts to. It is now hashed into the aux binding:

```
H_posture = SHA-256( "zs-posture-v1\0" || u8(0) )                                  absent
H_posture = SHA-256( "zs-posture-v1\0" || u8(1) || lenStr(plaintext_terminates)
                     || lenStr(upstream_base_url) || u8(zero_retention)
                     || u8(upstream_attested) )                                     present
aux       = SHA-256( "zs-aux-v2\0" || be64(node_id) || H_app || H_posture || nonce )
```

The node hashes the posture it derived from its **effective** config: after env overrides,
and after dstack's `${VAR}` substitution, which happens outside the compose hash. That is why
the verifier does not parse `NODE_CONFIG_YAML` out of `app_compose`: the literal text is not
what the node runs.

**Flag day, same shape as 9.9.** The aux tag moved to `zs-aux-v2`, so a 9.9 node's binding is
`aux_binding_mismatch` at a 9.10 verifier. `SplitReportData` is unchanged, and there is still
one rule. An absent posture is committed as absent rather than refused, so a relay can
neither strip one nor add one. A posture `HPosture` refuses (one that is not an object, a
wrongly typed field, or in Go a string field that is not valid UTF-8) gets the new tag
`posture_preimage_invalid`. Go's bundle decoder marks a wrongly typed posture
(`TEEPosture.Malformed`) instead of failing the whole bundle, as it already did for `nonce` and
`app_models`, so both languages report the same tag. `VerifyAux` / `verifyAux` take the bundle's posture as a new
argument, and `AuxBinding` / `auxBinding` take `H_posture`. Both are API breaks for every
caller.

**Verifier rule** (SPEC § 3e step 7): a `named_upstream` posture is admissible only if
`upstream_base_url` is `https`, carries no userinfo, and `inferDialect(url)` is `xai` with
`zero_retention` set, or the posture's new bound `upstream_attested` bit is set and the
bundle carries an `upstream_attestation` block with protocol `aci/1`
(`inject.UpstreamAttested` / `upstreamAttested`). The block is unsigned, so the bit is what
stops a relay adding one; the node sets the bit from `tee.upstream_attestation` being
configured, not from its lease, and omits the block while the lease is down.

**`InferDialect` matches exact hosts** (`inject.InferDialect`, plus a new TypeScript
`inferDialect`, pinned together by `testdata/dialect_vectors.json`). It used to match
substrings of the whole URL, so `https://api.x.ai.attacker.example`, `https://api.x.ai@attacker.example`
and `https://attacker.example/api.x.ai` all counted as xAI. Under `attested_passthrough`,
that let an operator send prompts to their own server under an attested-passthrough
verdict. It now takes the dialed host (`url.Parse` → `Hostname()`) and matches a vendor
domain on a label boundary. The accepted subset is deliberately narrow: a scheme, no
userinfo, a plain LDH host with no escapes, and no control byte or malformed `%` escape anywhere
in the URL. `HostMatchesDomain` refuses non-ASCII input. Go's `url.Parse` and WHATWG `URL` disagree at
the edges, and both sides must name the same host. A vendor name that is not the vendor's
own domain no longer infers a dialect, for example a proxy host with `moonshot` in its name.

## 9.9 — the other 32 bytes of `report_data` (minor, but BREAKING for `dstack-tdx`)

The upper half of the TDX `report_data` field was zero padding. It is now an **aux binding**:
a hash over the node's chain-resolved `node_id`, the model catalog it advertises on
`/v1/zs/details`, and an optional caller nonce. SPEC § 3e, "Model measurement".

```
H_app = SHA-256( "zs-happ-v1\0" || be32(n) || [lenStr(id) lenStr(src) lenStr(digest) u8(state)]… )
aux   = SHA-256( "zs-aux-v1\0" || be64(node_id) || H_app || nonce )
```

`TEEEvidenceBundle` gains two optional fields:

- **`app_models`**: the catalog entries the node hashed, so a verifier can recompute `H_app`.
  `weights_state` is a number: `1` measured, `2` declared, `3` unverifiable. `0` is refused.
- **`nonce`**: the caller's `?nonce=` challenge, echoed as hex. Absent on the cached bundle.

The node answers `GET /v1/zs/attestation?nonce=<64 hex>` with a freshly minted bundle that
it does not cache.

**Verifier rules** (`ReportDataHalves.VerifyAux` / `verifyAux`, pinned by the `aux_verify`
vectors):

- A verifier that sent a challenge refuses a bundle whose `nonce` is absent or different,
  then hashes its own challenge. A verifier that sent none hashes the bundle's `nonce` if
  present, or 32 zero bytes.
- An empty or absent `app_models` whose binding does not match is `happ_preimage_missing`.
  Any other mismatch is `aux_binding_mismatch`. An `app_models` that `HApp` refuses is
  `happ_preimage_invalid`. `AuxFailureTag` / `auxFailureTag` map errors to these tags.
- Entries are decoded strictly: a missing key, a null, or a value of the wrong type is
  refused with error `malformed_model_entry` (tag `happ_preimage_invalid`). Go and
  TypeScript defaulted such fields differently, so without this the two verifiers hashed
  different preimages for one bundle, and the TypeScript one accepted a measured entry that
  had no digest. The `h_app_json` vectors cover these shapes.
- Go matches bundle keys exactly, as JavaScript does, at the top level and inside
  `posture`, `collateral` and `upstream_attestation`, and refuses a body that is not valid
  UTF-8. TypeScript callers must decode with `parseEvidenceBundle`: `res.json()` replaces
  invalid bytes with U+FFFD instead of refusing them, so it would hash model ids differently
  from Go.
- A `nonce` that is not a string, or an `app_models` that is not an array, no longer fails
  the whole decode in Go. Go substitutes values `VerifyAux` refuses, so both languages
  return the same tag (`aux_binding_mismatch` or `happ_preimage_invalid`).
- A verifier's own all-zero challenge is refused (`zero_challenge`), since it hashes the
  same as no challenge.

**0.42.0 is incompatible.** `@txnlab/hayai-proto` 0.42.0 and the Go pseudo-versions at
`0f1825d` through `9f86b37` (the one node and proxy pinned) shipped 9.9 with `weights_state`
numbered 0/1/2 and a lenient TypeScript decoder. The same bytes mean different states there,
so nothing may pin these versions. Use 0.43.0 or later, and a Go pseudo-version at or after
the commit that carries this entry.

**This is a flag day.** `SplitReportData` used to require the upper half to be zero, and now
refuses a zero upper half as `aux_binding_absent`. There is no version switch. With that
error it still returns the lower half, so a verifier checks the key binding first and reports
a key mismatch as `key_binding_mismatch`.

**Why a minor bump.** `ProtoVersionCompatible` compares majors, so 9.8 and 9.9 stay
compatible for everything except dstack-tdx attestation, and non-TEE routing is unaffected. A
major bump would drop every plain node from routing for a rule they do not use. The cost:

- A 9.9 verifier refuses a 9.8 node with `aux_binding_absent`.
- A 9.8 verifier refuses a 9.9 node with `key_binding_mismatch`, because its
  `SplitReportData` requires the upper half to be zero. Deployed 9.8 code emits that tag;
  only upgrading the verifier changes it.

**Consequences.**

- A node can no longer present a sibling node's bundle: the aux binding hashes `node_id`
  (SPEC § 3e, "Why `report_data` omits `node_id`").
- `SplitReportData` no longer refuses a non-zero upper half, so it no longer stops a node from
  getting 32 bytes of its choice signed by real hardware. That now depends on the verifier
  calling `VerifyAux`.

## 9.8 — upstream attestation (minor)

One additive optional field on `TEEEvidenceBundle` (§ 3e), present only on a node whose
`tee.dataflow` is `attested_passthrough` and which verifies its upstream's enclave:

- **`upstream_attestation`** — `protocol`, `base_url`, `report_url`, `keyset_digest`,
  `verified_at`, `lease_expires_at`, `carve_outs`. It describes the enclave the node forwards
  plaintext **to**, and says nothing about the node itself.

**It carries pointers and digests, never the upstream's evidence, and that is the design.**
The evidence is fetchable by the payer directly from the upstream without an API key
(measured 2026-09-24 against `inference.phala.com`: `/v1/aci/attestation` and
`/v1/aci/sessions/{id}` both answer unauthenticated, the latter with a ~267 KB per-session
blob). Relaying it would add a quarter-megabyte to every `/v1/zs/attestation` fetch in order
to save the payer a request they should make anyway — **a report fetched with the payer's own
nonce proves freshness that a relayed one cannot.** The node's own verdict is deliberately
absent for the same reason a measurement is: a verdict is the one thing a payer must not take
from the party under appraisal.

**What a payer CANNOT re-check, and the block must not be read as implying otherwise.** The
appraisal half is independently reproducible — `report_url` with the payer's own nonce, the
keyset digest, the event-log replay, the compose gate. The **per-request** half is not: ACI/1
§ 7.6 binds a receipt to the credential that fetched it, so the receipts proving where each
individual prompt went are retrievable by the **node** and by nobody else. So this block says
"the enclave I forward to is one you can appraise yourself, and I check every response against
a signed receipt you cannot see." Both halves are real; only the first is verifiable from
outside.

**`carve_outs` is normative and must not be omitted when non-empty.** It names every rule the
node's upstream appraisal downgraded rather than enforced — today only
`root_backdoor_env:<ENV_NAME>`. Both of Phala's tiers declare a dstack root-shell env channel
that our own compose policy refuses on our own nodes, so an operator accepting one from an
upstream has conceded something a payer is entitled to see. A verifier MUST read a non-empty
`carve_outs` as **capping what a clean appraisal means**, not as a footnote on one: dstack
measures env *names* and not *values*, so nobody can tell whether the channel was used, and
RTMR3 records boot rather than runtime, so a shell changes what runs while every other check
keeps passing. An absent list means the node enforced every rule its policy carries; it does
**not** mean the policy was strict.

Minor rather than major: the field is optional and additive, and a 9.7 verifier that ignores
it reaches the same verdict about the node it already reached. What it loses is the ability
to see the upstream half at all, which is why a payer that does not recognize `protocol` MUST
treat the block as unverifiable rather than skip it and accept the rest.

**Conformance, stated rather than implied.** This change ships the **producer** — the node's
verifier, boot gate, per-request enforcement and this field. The payer-side MUSTs in § 3e
rules 1–4 are **not yet implemented** in `proxy/internal/hayai/attestation_dstack.go` or
`client/src/operators/tee-verify.ts`: both ignore the field, as they ignore any field a newer
node adds. That is inert today and stops being inert the moment a retention tier reads the
upstream half — a verifier that has not implemented rule 4 would then accept a tier it never
appraised. **So rules 1–4 are a prerequisite of that tier, not a follow-up to it**, and the
tier's own change must land them in both verifiers. Nothing executable spans producer and
consumer here, which is why it is written down.

> **Numbering note.** `plans/future/tee/report-data-aux-9-8.md` reserved 9.8 for a different,
> not-started design (filling the unused upper 32 bytes of `report_data`). That plan is
> design-stage and gated on an unanswered platform question, so the number went to the change
> that shipped, and the plan was renumbered to
> `report-data-aux-9-9.md` on 2026-09-24.

---

## 9.7 — node-carried Intel collateral (minor)

One additive optional field on `TEEEvidenceBundle` (§ 3e), present only on `dstack-tdx`:

- **`collateral`** — the Intel-signed collateral set for the quote's platform: PCK CRL, root
  CA CRL, TCB info for the quote's FMSPC, QE identity, each with its issuer chain. Field
  names and encodings mirror Intel's QVL structure verbatim, so both verifiers pass them to a
  third-party implementation untouched; `tcb_info` and `qe_identity` are the signed inner
  documents byte-for-byte, for the same reason `app_compose` is.

**It is a resilience fallback, and the spec says so in normative terms because the shape
invites the opposite reading.** A node cannot forge any of it — every document is Intel-signed
and re-validated against the verifier's own embedded Intel root — but nothing stops it
choosing which validly-signed *vintage* to send, and the only freshness bound a verifier can
apply is each document's own validity window (~30 days for TCB info). That is enough to
conceal a TCB level downgraded by a newer publication, or a PCK certificate revoked since the
CRL it sent. So: fetch from a PCCS first, use the carried set only when that fetch was
unreachable (never when a fetch ran and refused — that is an answer), apply a freshness floor
tighter than Intel's own, and treat a partial set as an absent one.

What it buys is availability rather than latency: a verdict during a PCCS outage or, for a
browser payer, a CORS regression — where the alternative is every confidential operator
reading as unverifiable at once. Absent is routine, not a verdict, so there is deliberately no
`PublishesCollateral` version gate to pair with `PublishesAppCompose`.

**Amended after both consumers implemented it: the precedence is three-deep, not two.** The
original rules said "PCCS, else this", which left the verifier's own cache of PCCS responses
unaddressed — and a verifier that has one holds a document whose vintage the operator did not
choose, i.e. strictly better evidence than the carried set. § 3e rule 2 now states the order
(PCCS → the verifier's own cache → the node's copy) and the two consequences that neither
implementation got right on the first pass: a cached document that was consulted and
**refused** the quote must not fall through to the carried set (that is the rollback rule 1
exists to prevent, applied to the one case where we already hold a signed "no"), and such a
refusal is nevertheless reported as `collateral_unreachable` rather than as invalid evidence,
because its cause is not attributable from the verifier's position. No wire change: the field,
its encodings, and its optionality are exactly as shipped.

---

## 9.6 — the compose preimage (minor)

One additive optional field on `TEEEvidenceBundle` (§ 3e), present only on `dstack-tdx`:

- **`app_compose`** — the dstack `app-compose.json` document verbatim. It is the **preimage**
  of the `compose-hash` the RTMR3 replay recovers: `sha256(app_compose)` equals that
  measurement exactly, which is a property of how dstack builds the digest, not a convention
  we chose.

**Why this does not contradict 9.5's "no `compose_hash` field, deliberately".** That rule bans
a self-reported *measurement* — a value a verifier could read instead of replaying. This is the
opposite object: bytes whose only use is to be hashed and compared against the replay's own
answer. Substituting a friendlier document moves the digest, so there is nothing here to trust,
and the cheap-wrong-implementation failure the rule guards against is not available — a verifier
that skips the hash check is not reading a measurement, it is reading an operator-authored
document with no measurement attached.

**What it buys, which is the reason it exists.** `compose-hash` covers the operator's own
configuration, so it is distinct per operator *and per redeploy*. Nothing can enumerate that, so
a hash allowlist did not scale past a handful of hand-blessed nodes — which left `dstack-tdx`
verifiers checking that a node was measured without ever checking **what** it runs. With the
preimage in hand a verifier checks the document's *content* against per-release rules, and what
remains enumerable is a per-**release** list.

Three rules ride with it, each stated in § 3e because each is a way to implement this and get a
well-formed wrong answer:

- **Hash first, read second.** A verifier that reads a single field before checking the digest
  has verified nothing at all.
- **Carried byte-for-byte.** Any re-encoding — including a re-marshal that only reorders keys —
  moves the digest and makes the bundle unverifiable everywhere while looking fine at the node.
- **Absent or empty is never a check that passed — and never automatically a rejection
  either.** An empty document still hashes to a well-formed digest, so the tempting shape is to
  skip quietly and report clean; that is the reading § 3e forbids. Refusing outright is equally
  wrong today, because every guest agent predating 9.6 publishes nothing and a hard failure
  would report an honest fleet as compromised. The verifier records that the compose was not
  content-validated and may still accept the node through a hand-configured hash allowlist.

The node self-verifies the same equality before publishing, for the same reason it already
replays its own event log: otherwise it advertises evidence every relying party rejects, and
nothing in its own logs says why. A node that *cannot* produce a preimage — its guest agent
does not publish the document, or its event log carries no `compose-hash` to anchor it to —
publishes the quote and event log without it rather than going dark. `wire.AppComposeMinVersion`
/ `publishesAppCompose` is what lets a verifier tell that case from a 9.6 node withholding it:
absent from a pre-9.6 peer is a build fact, absent from a 9.6 peer is about the node.

**The content rules, and the shape of the `docker_compose_file` check.** Both reference
verifiers now call `VerifyAppCompose` — the proxy at step 4c of its dstack verifier, the browser
client at step 4b — each hashing the document against its own replay before reading a field.
`trusted_compose_hashes` remains the proxy's actual gate; the content rules are an additional
filter, and the case they catch that a hash allowlist structurally cannot is a node whose hash
someone blessed by hand that nonetheless declares `DSTACK_AUTHORIZED_KEYS`.

`docker_compose_file` is checked by a **whole-file template match**, not a deny-list. A verifier
lifts out the two spans an operator may vary — the `image:` reference and the
`NODE_CONFIG_YAML:` block body — hashes the rest as text against published release *skeletons*,
and checks the image against a list of published release images. Nothing enumerates what is
forbidden: a bind mount, a `privileged: true`, a second service, an extra port are all text the
release compose does not contain. (A second service became admissible on 2026-09-02, under the
two conditions recorded in the unversioned section at the top; everything else in this
paragraph still holds.) This replaced an enumerated deny-list because enumerating
hazards over YAML needs a parser per language, and two parsers disagreeing about anchors or
duplicate keys is two verifiers reaching opposite verdicts on identical evidence, silently. The
cost is real and is the operator's: the compose becomes a published artifact, comments included,
and reformatting it is indistinguishable from tampering.

**The template match is in force.** `ZeroSignalComposePolicy` still leaves `EnforceComposeSkeleton`
unset with empty lists — the per-release data moves on each consumer's own cadence, like the
trusted OS-image list — but both shipped consumers now supply it: zs-proxy from its config
defaults and the browser client from a bundled constant. So a clean `VerifyAppCompose` on either
of them now means "runs a published zs-node release", not "nothing structurally disqualifying".
Two rules come with that, both in § 3e: a whole-document pin such as `trusted_compose_hashes`
narrows and must never substitute for the release match, and an absent `app_compose` preimage is
**refused** rather than skipped wherever the match is enforced — the skip was only ever safe
behind a hand-blessed digest. A library caller taking the shared policy verbatim still gets the
weaker check and should say so.

**Also in this release, from review of the above.** Go's `strings.TrimSpace` and JavaScript's
`String.prototype.trim` are different predicates — U+0085 is space to Go only, U+FEFF to JS only
— and using each language's built-in put a verdict split into the compose rules at eleven call
sites. Both now use one explicitly-written ASCII class for value normalization and one
explicitly-written union class for the vacuous-document test, and
`proto/testdata/compose_vectors.json` pins every observable across the two languages. That file
is what caught the remaining divergences: a `docker_compose_file` of one invisible character
sidestepped `empty_docker_compose` entirely, and `null` was malformed in one language and a pile
of policy violations in the other.

## 9.5 — dstack TDX attestation mode (minor)

`tee.mode` gains `"dstack-tdx"`: an Intel TDX confidential VM managed by dstack (Phala Cloud
and self-hosted dstack alike). CPU-only — it carries no `gpu_eat` and makes no NRAS call — so
its verifier branch is disjoint from the `nvidia-cc-*` ones rather than a case inside them.

Two additive fields on `TEEEvidenceBundle` (§ 3e), both absent on every existing mode, so the
`nvidia-cc-*` wire shape does not move a byte:

- **`event_log`** — dstack's runtime measurement log, as raw JSON. It exists because dstack
  extends RTMR3 with a log rather than publishing measurements directly, so a verifier
  *recomputes* `compose-hash` and `os-image-hash` by replaying it against the hardware-signed
  RTMR3. Untrusted input whose only power is to be checkable, which is what makes it safe to
  take from the node.

  There is deliberately **no `compose_hash` / `os_image_hash` field**. Carrying them would
  invite a verifier to read the self-report instead of replaying — a cheap wrong verifier that
  is indistinguishable from the correct one on every honest node.

- **`posture`** — where plaintext comes to rest: `in_enclave`, or `named_upstream` plus the
  one API it is forwarded to. A quote says which software ran; it does not say whether that
  software keeps the prompt. The block is a **routing hint the verifier cross-checks against
  the allowlisted measurement**, never the authority — reading it as evidence gets you a claim
  signed by nobody. Contrast the trust *tier*, which is the verifier's own conclusion and
  never travels on the wire at all.

Also pinned in § 3e, because each is the kind of check that reads as covered while being
vacuous: the vendor chain is selected from the **report bytes** (TDX v4 `tee_type == 0x81`),
never from the node-authored `mode`; `report_data` is checked in **both halves** (`[32:64]`
must be zero, or the high half is a free "get Intel to sign 32 attacker-chosen bytes" oracle);
and the replay fails closed on a zero-event replay, an all-zero RTMR3, or an undecodable
payload.

## 9.4 — built-in tool round actions (minor)

The sealed status frames of SPEC §5.3.1 (`response.zs_tool_call.in_progress` / `.completed`)
gain an optional `action` object describing what the round is actually doing —
`{"type":"search","query":…,"sources":[…]}` for `zs_web_search` / `zs_image_search` and
`{"type":"open_page","url":…}` for `zs_web_read` — so a streaming client can render
"Searching for X" and list sources as they land instead of a bare "Searching the web".

The shape mirrors OpenAI's `web_search_call.action`, so a consumer that already renders
OpenAI's native web search renders ours with the same code. Sources carry a URL and no
title: that matches OpenAI's source shape, and the URL/title pairs already reach the client
as `url_citation` annotations, so the scraped third-party title never needs to ride a frame.

**Favicon bytes, not URLs.** The completed frame's action also carries an optional `icons`
map — each source site's favicon, as bytes, keyed by lowercased host. A ZeroSignal extension
with no OpenAI counterpart, carrying bytes rather than a URL on purpose: a consumer
rendering `<img src="https://thatsite.com/favicon.ico">` would disclose its IP and a render
timestamp to every host in a search result — an attacker-influenceable set, since results
come from a third-party backend steered by a model-chosen query — which makes it a beacon
channel rather than a decoration. Inlined and sealed, a relay learns nothing and the consumer
contacts nobody. Keyed by host rather than nested per source so several results from one site
share one copy. The MIME is sniffed from the bytes, never read off the serving site's
`Content-Type`, and `image/svg+xml` is excluded: SVG is an active document format and these
bytes end up inlined in a consumer's page. See `tools.IconMimeFromBytes` / `tools.IconHostKey`.

**Why a minor**, and weaker than 9.1–9.3: one optional field on an existing sealed frame, on
a channel whose consumers already skip unknown shapes by spec (§5.3.1's "MUST treat unknown
`type` values as skippable"). No canonical-bytes, signing-tag, or envelope-shape change, and
nothing is REQUIRED of any peer, so there is no capability predicate or min-version constant:
the proxy never reads the sealed plaintext, a 9.3 client against a 9.4 node ignores the
field, and a 9.4 client against a 9.3 node sees it absent. Both render today's generic labels.

**One deliberate asymmetry**: `zs_web_read` carries NO action on the `in_progress` frame.
Those frames are emitted for every call in an iteration BEFORE any of them run, while the
read's provenance gate runs later, per-call — so advertising the URL up front would render
"Reading \<attacker URL\>" in the caller's UI for a read the node then refuses, handing
attacker-chosen text a trusted-looking surface. Its URL appears only on the completed frame,
sourced from `ToolEffect.Action`, which the loop sets on the success path alone (gate-passed
AND returned without error). See `tools.ActionForCallPreflight`.

Landing this also tightened the terminal-frame classifier next door (`stream_terminal.go`):
putting the model's own words on a sealed frame meant a prompt could contain the literal
string `response.completed` and trip a raw-substring match, letting caller content steer a
payer-safety verdict. The `/v1/responses` path now confirms the frame's top-level `type`
after the substring prefilter. Vectored, mirrored in TS, and not itself a wire change — a
classifier reads bytes that were always shaped this way.

## 9.3 — long-context surcharge pricing (minor)

`/v1/zs/details` gains four advertised `long_context_*` fields
(`long_context_threshold_tokens` plus high-tier input / output / cache-read rates) so an
operator can price the context-size cliff xAI (Grok) bills with — a prompt at or above the
threshold pays a higher rate set for the whole request.

No canonical-bytes or signing-tag change: the tier is resolved at reserve from the ticket's
already-signed `input_count` (`pricing.IsLongContext`) and the tier-appropriate rates are
pinned onto the EXISTING `InputRate` / `OutputRate` / `CacheReadRate` ticket fields, so the
ticket and receipt digests are untouched. Nothing is required of a peer — the fields are
additive JSON a 9.0/9.1/9.2 node omits and a 9.3 verifier resolves the base tier for.

**Backward compat during rollover holds, but only just**, and it depends on a node-side
validation rule rather than on luck alone:

- **Input/output rates**: an old, non-tier-aware verifier bounds a tier-2 ticket's signed
  rates against base × `RateMaxMultiple` (2.0), so a legitimate exactly-2× surcharge passes
  (boundary `<=` — a coincidence, not headroom). Any future >2× tier requires tier-aware
  verifiers deployed first.
- **The cache-read rate has no such coincidence**, because a discount makes the high/base
  ratio far larger than 2×. A tier whose high cache-read rate is omitted advertises only the
  BASE discount, and an old verifier then bounds the high-tier ticket's cache-read rate
  against base × 2.0 and refuses every one of them. The node therefore RESOLVES an unset high
  cache-read rate to the base one scaled by the input rate's step-up whenever the base tier
  discounts, and refuses a config that explicitly declares no high-tier discount while the
  base has one — so the high rate is always advertised and the old verifier bounds
  like-for-like.

## 9.2 — tightened reserve input-token bound (minor)

Adds `tokenize.InputTokenBoundV2` and the `input_bound_version` field that selects it on the
reserve request. Nothing about canonical bytes, signing tags, or envelope shape changes, and
the capability is negotiated per-request rather than assumed, so 9.0/9.1/9.2 nodes stay in
each other's candidate and relay pools.

A caller only sizes with v2 against a node advertising >= 9.2 (`UsesTightInputBound`);
everyone else keeps sizing with v1, which every 9.x node still implements and enforces. The
gate is load-bearing in one direction and merely wasteful in the other: sizing v2 against a
pre-9.2 node is a hard failure — v2 is TIGHTER than v1 on prose, tool schemas, and images, so
the node's v1 measurement of the same body exceeds the smaller reserved `input_count` and
admission fails closed with `input_budget_exceeded`. Sizing v1 against a 9.2 node merely
over-reserves, and the node honours the declared version, so nothing breaks.

## 9.1 — relay hop marker (minor)

A relaying node now sets `RelayHopHeader` (`X-Zs-Relay-Hop`) on every response it produces on
`RelayPath`, and skips that key when copying the target's headers back — so its presence
proves the relay's own handler ran, and its ABSENCE (from a node advertising >= 9.1) proves
the request died at the relay's front door without reaching it.

That distinction was previously unavailable: a CDN 504 in front of the relay and a target's
504 forwarded verbatim were byte-identical, both classified `transient.AttrUnknown`, so
neither hop was ever charged and a relay behind a broken gateway stayed in rotation while
every draw benched a healthy target.

**Why a minor, and the distinction is load-bearing**: `ProtoVersionCompatible` is
major-EQUALITY, so 9.0 and 9.1 nodes remain in each other's candidate and relay pools. A 9.0
relay simply doesn't set the header, a 9.1 caller reads its absence as no-evidence
(`SetsRelayHopHeader` returns false), and nothing is dropped. A major would partition the
fleet over a diagnostic header. No canonical-bytes or signing-tag change — the same additive
shape as the 7.1 videoprice and 8.1 payer-sig minors.

## 9.0 — cached-token pricing (major)

`Ticket.CanonicalBytes()` gained `CacheReadRate` and `UsageReceipt.CanonicalBytes()` gained
`CachedInputCount`, both appended at their respective tails, and the ticket and receipt
signing tags bumped their v1 → v2 generation — so 8.x and 9.0 ticket *and* receipt signatures
are mutually unverifiable (a hard pre-image break on BOTH digests, the direct analog of the
5.0 usage-type bump).

Lets an operator price the cached-read subset of the prompt (tokens an upstream served from a
prefix/prompt cache) at a discounted `CacheReadRate` instead of the flat `InputRate`; the node
signs the cached count onto the receipt so the proxy can verify the discount it was charged.
Without the major bump a 9.0 caller would treat an 8.x node as compatible and only fail at
ticket/receipt verification after a wasted reserve. Not a contract redeploy, but the whole
fleet still cuts over together, like 5.0.

## 8.1 — reserve-request payer signature (minor)

`ReserveRequest` gained two optional fields inside the sealed body — `payer_sig` (base64
Ed25519 over the new `zs-reserve-v1\x00` canonical bytes) and `payer_issued_at` —
authenticating `payer_addr` so the node's per-account limiter, funds gate, and abuse tracking
key on a proven identity instead of a spoofable claim (SPEC.md §3a "Reserve-request
signature"). The signature also binds the target `(operator_id, node_id)` and
`proxy_recipient` as unsent signed context.

**Why a minor**: the fields are additive JSON an 8.0 node ignores, and a node accepts a
missing signature until its `zs.require_payer_sig` knob flips (verify-if-present) — so 8.0 and
8.1 peers interoperate. Mirrors the videoprice 7.1 additive-minor precedent; no new
signing-tag break for the existing digests (`zs-reserve-v1` is a fresh, independent domain).
The later enforcement flip is operational, not a wire change.

## 8.0 — relay metadata minimization (major)

The relay now forwards opaque bytes in BOTH directions on BOTH legs. 3.0 sealed the reserve
*request* and declared that a relay "cannot read the payer"; that was not true, because three
cleartext channels survived and a relay forwards a request's reserve and inference legs alike
(see `relay.exactAllowedInnerPaths`). All three close here, and **they only close together** —
leaving any one open re-exposes the payer to the same relay on the same request:

- **(a)** The reserve RESPONSE is sealed to `proxy_recipient` (`SealedReserveResponseContentType`
  / `SealReserveResponse`). Its `presigned_open_txn` named the payer twice, decodable with no
  chain lookup.
- **(b)** The inference REQUEST envelope is ciphertext-only: `algorand_tx_id`, `ticket_id`,
  `admission_tag`, and `reply_to_public_key` moved into an age-sealed inner-request frame
  (`inner.go`). The first two resolve to the payer via the `open()` tx and the `TicketRecord`
  box.
- **(c)** The inference RESPONSE metadata is sealed under `K_response` with the new header AAD
  (`BuildHeaderAAD` / `SealHeader`): `X-Zs-Receipt` and `X-Zs-Settle-Group`, plus the
  `zs-settle-group` SSE frame, which previously shipped the payer-ack template — payer address
  in cleartext — on the reasoning that its txns go on chain anyway. True for a chain observer;
  false for a relay that also holds the client IP.

`ResponseEnvelope` drops its `algorand_tx_id` echo as part of (b): both sides reconstruct the
AAD from state they hold, so the echo only fed the relay.

The AAD *layout* and every signing tag are unchanged from 7.0 — a framing break, not a crypto
one — but a 7.0 envelope decrypts to a body with no inner-request magic and is rejected, and a
7.0 caller cannot parse a sealed reserve response, so the majors must not mix. **The residual
is timing**: `open()` is a public transaction, so a relay can still correlate
(client IP, target, τ) against the chain. See SPEC.md §3f.

## 7.0 — full hayai → zs rename (major)

Two breaks ship together:

- **(a) Transport labels.** The `X-Hayai-*` HTTP headers became `X-Zs-*`; the SSE event tags
  `hayai` / `hayai-receipt` / `hayai-settle-group` / `hayai.usage` became `zs` / `zs-receipt` /
  `zs-settle-group` / `zs.usage`; the envelope MIME `application/vnd.hayai+json` (and the
  sealed-reserve `…-reserve+json`) became `application/vnd.zs+json`; and the HTTP routes
  themselves — `/v1/hayai/{details,reserve,relay,operators,attestation}` — became `/v1/zs/{…}`.
  The OpenAI-compat routes (`/v1/models`, `/v1/chat/completions`, `/v1/responses`, …) are
  untouched.
- **(b) Cryptographic domain-separation tags.** The AAD protocol tag (`aadProtocolTag`
  `"hayai"` → `"zs"`) AND every signing domain (`AdmissionTagDomain`, `ticketSigningTag`,
  `receiptSigningTag`, the ephemeral tag) were renamed `hayai-*` → `zs-*` AND every suffix was
  reset to v1, giving `zs-admission-v1` / `zs-ticket-v1` / `zs-receipt-v1` / `zs-ephemeral-v1`
  — a fresh `zs-*` namespace with a clean v1 baseline. This changes every signature digest AND
  every AEAD AAD, so 6.0 and 7.0 signatures and sealed frames are mutually unverifiable: a hard
  crypto break, not just a framing one. The canonical-byte LAYOUT is unchanged (field order and
  encoding identical to 6.0); only the domain-tag bytes differ, and the suffix reset is cosmetic
  (the prefix change alone already breaks compat). Not a contract redeploy.

Either break alone already makes 6.0 and 7.0 peers non-interoperable.

**Note how (a) changed the way a cross-major mismatch surfaces.** Earlier majors kept
`/v1/hayai/details` stable, so a caller could read a peer's `proto_version` and drop it with an
explicit version-mismatch. Under 7.0 a 7.0 caller probes `/v1/zs/details`, so an un-upgraded
6.0 node (still serving `/v1/hayai/details`) returns 404 and is dropped as *unreachable* rather
than *version-incompatible* — a blunter signal, but the node is excluded from the candidate set
either way, which is the only property the filter needs on a hard cutover.

## 6.0 — ephemeral advertisement binds node_id (major)

The `EphemeralAdvertisement` signed canonical bytes gained `u64(NodeID)` right after
`OperatorID` and the ephemeral signing tag bumped v2 → v3, closing the sibling-node
substitution hole: under 5.0 an operator that reused one signing key across its nodes could
have node A's advert validate as node B's, sealing traffic to a key node B cannot decrypt.

v2 and v3 ephemeral signatures are mutually unverifiable, so a 6.0 verifier rejects every 5.0
node's advertisement and vice versa — the version filter drops them up front instead of failing
at the ephemeral-verify step after a wasted probe. Ticket and receipt canonical bytes and tags
are unchanged from 5.0.

## 5.0 — usage-type wire bump (major)

`Ticket` AND `UsageReceipt` `CanonicalBytes()` gained `UsageType` discriminators at the tail
and the ticket and receipt signing tags bumped to their v2 generation — so 4.0 and 5.0 ticket
*and* receipt signatures are mutually unverifiable (a hard pre-image break on BOTH digests,
unlike 4.0, which left `UsageReceipt` unchanged).

Shipped with dedicated-route image microUSDC pricing (`imageprice`) plus the price-independent
`serves_image_gen` / `serves_image_edit` eligibility flags. 4.0 left the signing tags at v1, so
without this bump a 5.0 caller would treat a 4.0 node as compatible and only fail at
ticket/receipt verification after a wasted reserve.

## 4.0 — operator/node split (major)

The off-chain `Ticket` now carries `node_id`, and `Ticket.CanonicalBytes()` commits to it right
after `operator_id` — so 3.0 and 4.0 ticket signatures are mutually unverifiable (a hard
pre-image break, the same gating role as the 2.0 digest change).

Shipped alongside the fresh-deploy `ZeroSignalEscrow` contract that splits `OperatorRecord`
into a per-owner operator plus many `NodeRecord` boxes; `/v1/zs/details` advertises
`(operator_id, node_id)`. The whole fleet cuts over together with the new app id.
`UsageReceipt` canonical bytes are unchanged.

## 3.0 — transport privacy activated (major)

Single-hop operator-as-relay (SPEC.md §3f). The relay route and selection primitive shipped
DORMANT at 2.0; 3.0 turns them on: privacy defaults ON at the proxy and client, and the reserve
request body is now sealed confidentiality-only (`SealedReserveContentType` /
`SealReserveRequest`) so a relay can no longer read the caller's `payer_addr`.

There is no relay capability flag, so the version-negotiation filter (`ProtoVersionCompatible`
→ `pickCandidates`) drops every pre-relay 2.0/1.0 node from relay-using candidate sets. A 3.0
node only ever talks to 3.0 peers, so the node's reserve handler is sealed-only (415 on
plaintext).

## 2.0 — ticket/receipt digest prefix removal (major)

Removed the obsolete `"MX"` prefix from the ticket and receipt signing digest. The digest is
now `sha256(domain_tag || canonical_bytes)` with the domain tag living inside
`CanonicalBytes()` (unchanged); the pre-image differs from 1.0 by two bytes, so 1.0 and 2.0
signatures are mutually unverifiable.

## 1.0 — initial generation

The baseline. Also the value `LegacyProtoVersion` substitutes for a missing `proto_version`
field on the wire, which marks pre-field nodes incompatible with every current caller.
