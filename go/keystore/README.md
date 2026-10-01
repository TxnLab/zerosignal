# keystore

How the node and the proxy load Algorand mnemonics at startup. This is the single canonical reference — `node/AGENTS.md`, `proxy/AGENTS.md`, and the `config.example.yaml` files all link here.

## Provider chain

`keystore.LoadFromEnv(ctx)` (called from `node/main.go` and `proxy/main.go`) consults two providers in order:

1. **`EnvProvider`** — scans the OS environment for variables ending in `_MNEMONIC` and strips the suffix to derive a label.
2. **`URLProvider`** — fetches one mnemonic per URL listed in `ZS_MNEMONIC_URLS`. Dispatches per URL scheme.

Mnemonics from any source are decoded into Ed25519 private keys and indexed by their derived Algorand address. The label (`OPERATOR_SIGNING`, `payment`, etc.) is informational only — lookups are by address.

## Env-var form (cheapest; recommended for dev)

```
OPERATOR_SIGNING_MNEMONIC="word1 word2 ... word25"
PAYMENT_MNEMONIC="word1 word2 ... word25"
```

Any var whose name ends in `_MNEMONIC` is picked up. Empty values are skipped. The label is everything before `_MNEMONIC`.

## Mnemonic forms (25-word Algorand or 24-word xHD)

Each loaded mnemonic is one of two forms, dispatched on word count — no extra config:

- **25 words** — a standard Algorand mnemonic, decoded straight to its ed25519 private key.
- **24 words** — a BIP-39 / ARC-52 xHD recovery phrase, the form the `client/` chat app exports from its passkey-derived wallet. The keystore validates the BIP-39 checksum, then derives the **first indexed account** `m/44'/283'/0'/0/0` with the Peikert variant. This is exactly the client's `keyGen(KeyContext.Address, 0, 0)`, so pasting the phrase a user exported loads the **same Algorand address** they see in the client. The address is logged at load (`kind=xhd-24`).

A 24-word xHD key's signing scalar is derived through BIP32-Ed25519 and is not representable as a 32-byte ed25519 seed, so it signs through the extended key — but the signatures verify under standard ed25519 against the derived address, so escrow transactions and ZeroSignal tickets sign and verify identically to a 25-word key.

The seed uses an **empty BIP-39 passphrase** (matching the client). A passphrase-protected phrase still passes the checksum but derives a *different* address, so it would silently load the wrong account — out of scope by design.

Derivation uses [`github.com/algonode/go-algorand-hd-wallet`](https://github.com/algonode/go-algorand-hd-wallet) (xHD derivation + signing) and `github.com/tyler-smith/go-bip39` (checksum + seed). The HD lib is **pinned to an exact version**: it sits on the signing path, so a bump must be deliberate and must re-run the golden-vector tests in `keystore_hd_test.go`, which cross-check derived addresses against the client's `@algorandfoundation/xhd-wallet-api` output (regenerate via `client/`'s `entropyToMnemonic → mnemonicToSeedSync → fromSeed → keyGen` pipeline). Those vectors guard `m/44'/283'/0'/0/0` specifically — extend them if the derivation path is ever parameterized.

## URL form (production; cloud-backed)

```
ZS_MNEMONIC_URLS="signing=awssecretsmanager://arn:...,payment=gcpsecretmanager://projects/PROJECT/secrets/NAME/versions/latest,backup=azurekeyvault://VAULT/SECRET"
```

Comma-separated `name=url` pairs. Whitespace around names and URLs is trimmed.

### Supported schemes

| Scheme | Backend | Notes |
|---|---|---|
| `awssecretsmanager://<arn>?region=us-east-1` | AWS Secrets Manager | via `gocloud.dev/runtimevar` |
| `awsparamstore://<path>?region=us-east-1` | AWS SSM Parameter Store | via `gocloud.dev/runtimevar` |
| `gcpsecretmanager://projects/PROJECT/secrets/NAME/versions/latest` | GCP Secret Manager | via `gocloud.dev/runtimevar` |
| `azurekeyvault://<vault-name>/<secret-name>` | Azure Key Vault | direct via `azsecrets`; gocloud has no Key Vault driver for runtimevar |
| `file:///absolute/path/to/mnemonic?decoder=string` | Local file | via `gocloud.dev/runtimevar/filevar`; useful for tests + safe-to-commit configs that point at a gitignored file |

### Authentication

Each backend uses its standard credential discovery — nothing keystore-specific:

- **AWS:** `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_PROFILE`, IAM role on EC2/ECS/EKS.
- **GCP:** Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, GKE workload identity).
- **Azure:** `azidentity.NewDefaultAzureCredential` — managed identity → env vars (`AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_CLIENT_SECRET`) → `az login`.

The Azure credential is resolved lazily on the first `azurekeyvault://` URL — binaries with no Azure URLs never trigger the managed-identity probe.

## Validation

After load, the keystore is keyed by Algorand address. Binaries that need a specific address (the node needs `zs.signing_addr`) call `ks.HasAccount(addr)` and refuse to start if it isn't loaded. Mismatched mnemonics surface as a missing address, not a silent successful start.

## Mixing sources

A keystore can hold mnemonics from multiple sources at once — env vars and URLs coexist. Duplicate addresses are tolerated (the second occurrence is logged and skipped) so a fallback chain doesn't break the load.

## What it isn't

- **No YAML config field for mnemonics.** Plaintext secrets in YAML files end up in git history too often. Use env vars (in your shell or `.env`) or a `file://` URL pointing at a gitignored path.
- **No runtime reload.** Mnemonics are loaded once at startup; rotating a key means restarting the binary with new provider config.
- **No Azure runtimevar driver.** `gocloud.dev/secrets/azurekeyvault` exists but is for KMS encrypt/decrypt, not for fetching secret values, so the URL provider wraps `azsecrets` directly for the `azurekeyvault://` scheme.

## Interfaces

- `keystore.KeyStore` satisfies `proto.BytesSigner` (used by `proto.Ticket.Sign`) and `proto/algo.MultipleWalletSigner` (used by raw txn signing and `AtomicTransactionComposer` adapters). Those are the only two signing framings it offers, deliberately: `BytesSigner.SignBytes` signs verbatim, because ticket / receipt / advertisement signing hands it a precomputed sha256 digest of a domain-tagged canonical body.
- Add a custom backend by implementing `SecretProvider` (one method: `Mnemonics(ctx) ([]MnemonicEntry, error)`) and passing it to `keystore.New`.
