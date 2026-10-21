/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Discovery: the on-chain operator and node set and the details probes that
// fill it in (Go's ChainOperatorSource), the registry that refreshes them on a
// schedule (Go's DynamicRegistryProvider), and the catalog it saves.

export {
    type ApplicationBox,
    BoxValuesUnsupportedError,
    ChainOperatorSource,
    type ChainOperatorSourceOptions,
    type ChainReadOptions,
    type ChainReader,
    FETCH_BOX_CONCURRENCY,
    NoOperatorsError,
    SIGNER_BALANCE_CONCURRENCY,
    SIGNER_BALANCE_TIMEOUT_MS,
    deploymentOrFail,
    fetchAllOperators,
    fetchNodesForOperators,
    fetchOperatorsById,
    listApplicationBoxes,
    nextOperatorId,
    readNodeBox,
    readDeploymentId,
    readOperatorBox,
    resolveOperatorNode,
} from './chain.js'
export { SolanaChainReader, type SolanaChainReaderOptions, resolveSolanaNode } from './solana.js'
export {
    DEFAULT_DETAILS_CONCURRENCY,
    NodeProber,
    type ProbeOptions,
    type ProbeOutcome,
    type ProbeOutcomeFields,
    applyProbeOutcome,
    classifyProbeFailure,
} from './probe.js'
export { aggregateBuiltinTools, aggregateModelDetails, aggregateModels } from './aggregate.js'
export {
    CATALOG_FORMAT_VERSION,
    CATALOG_STORAGE_KEY,
    decodeCatalog,
    loadCatalog,
    marshalCatalog,
    saveCatalog,
} from './persist.js'
export {
    BOOT_FETCH_TIMEOUT_MS,
    DiscoveryRegistry,
    type DiscoveryRegistryOptions,
    type OperatorSource,
    type RegistrySnapshot,
    STORAGE_TIMEOUT_MS,
    advertisable,
    carryCaps,
    carryForwardLastGood,
    mergeCatalog,
} from './registry.js'
