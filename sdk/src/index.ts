/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// @txnlab/zerosignal: the ZeroSignal payer SDK, the TypeScript twin of
// github.com/TxnLab/zerosignal/go/zs. Names and semantics are shared with it;
// signatures are idiomatic to each language. The protocol primitives are under
// @txnlab/zerosignal/proto.

export * from './ack.js'
export * from './admit.js'
export * from './affinity.js'
// The transport; the retry rules under it stay internal.
export {
    ALGOD_MAX_RETRIES,
    ALGOD_RETRY_WAIT_MAX_MS,
    ALGOD_RETRY_WAIT_MIN_MS,
    AlgodHTTPError,
    type AlgodTransportOptions,
    RetryingAlgodClient,
    retryingAlgod,
} from './algod-transport.js'
export { type BuiltDiscovery, type RoutingStores, buildDiscovery, catalogStorageKey, chainAlgod, solanaRpc } from './assemble.js'
export { type SolanaRpcClient, txErrorName } from './solana/rpc.js'
// For a host's own Solana transactions, which wait as the SDK's do.
export { type ConfirmOptions, TransactionExpiredError, confirmSignature } from './solana/confirm.js'
export * from './attestation.js'
export * from './client.js'
export * from './config.js'
export * from './decode.js'
export * from './details.js'
export {
    type DoctorCheck,
    type DoctorNode,
    type DoctorReadings,
    type DoctorReport,
    type DoctorStatus,
    diagnose,
    doctorChecks,
} from './doctor.js'
export { type SolanaDoctorReadings, solanaDoctorChecks } from './solana/doctor.js'
export { SolanaTicketGoneError, SolanaWallet, type SolanaWalletOptions, readSolanaConfig } from './solana/wallet.js'
export {
    NoRentPoolError,
    RentDepositBelowTargetError,
    RentDepositUnconfirmedError,
    RentPoolTicketsOpenError,
    RentPoolUnconfirmedError,
    SolanaRentPool,
    type SolanaRentPoolOptions,
    type SolanaRentPoolStatus,
    readSolanaRentPool,
    rentPoolAvailable,
    rentPoolBackedSlots,
    rentPoolFreeSlots,
} from './solana/rent.js'
export {
    type SolanaPayerTicket,
    type SolanaPayerTickets,
    type SolanaUnreadableTicket,
    fetchSolanaPayerTickets,
} from './solana/tickets.js'
export {
    type CreditIssuer,
    type CreditKey,
    type CreditStore,
    CreditsExhaustedError,
    FREE_CREDIT_DEFAULTS,
    type FreeCredits,
    type HttpCreditIssuerOptions,
    creditIssuersFor,
    httpCreditIssuer,
    memoryCreditStore,
} from './solana/credits.js'
export * from './errors.js'
export * from './escrow/index.js'
export * from './estimate.js'
export * from './events.js'
export { FEE_RATE_CACHE_TTL_MS, FEE_RATE_REFRESH_TIMEOUT_MS } from './fee-rate.js'
export { SHOULD_RETRY_HEADER } from './fetch/errors.js'
export { FETCH_BASE_URL, type FetchOptions, type FetchTarget, MAX_CLIENT_BODY_BYTES, openAIFetch } from './fetch/serve.js'
export { type CatalogSource, MODELS_OWNED_BY } from './fetch/models.js'
export { USAGE_FRAME_EVENT, USAGE_FRAME_HEADER } from './fetch/usage.js'
export * from './hostguard.js'
export { DEFAULT_STREAM_IDLE, type StreamIdle, type StreamIdlePhase, StreamIdleTimeoutError } from './idle.js'
export * from './privateip.js'
export * from './mbr.js'
export * from './network.js'
export * from './nofit.js'
export * from './operator.js'
export * from './pacing.js'
export * from './parts.js'
export * from './ports.js'
export * from './reconcile.js'
export type { RefundWatchdog } from './refund-watchdog.js'
// The registry and its source; the fetchers and the cycle rules under them stay internal.
export {
    CATALOG_STORAGE_KEY,
    ChainOperatorSource,
    type ChainOperatorSourceOptions,
    type ChainReader,
    DiscoveryRegistry,
    type DiscoveryRegistryOptions,
    type OperatorSource,
    type RegistrySnapshot,
    SolanaChainReader,
    type SolanaChainReaderOptions,
} from './registry/index.js'
export * from './request-parse.js'
export * from './reserve.js'
export * from './reserve-price.js'
export * from './reserve-retry.js'
export * from './response.js'
export * from './seal.js'
export * from './sizing.js'
export type { SettleResult } from './receipt-check.js'
export type { Request, Stream } from './turn.js'
export * from './types.js'
export * from './verify.js'
export * from './wallet.js'
