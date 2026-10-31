#!/usr/bin/env node
// Re-records testdata/attest/ds_collateral.json: Intel's collateral for the
// capture's platform (testdata/attest/ds_quote_hex.txt), fetched through the
// real @phala/dcap-qvl getCollateral from the mirror nodes default to, and
// stored in the TEECollateral wire shape. tee-pccs-real.test.ts feeds it back
// to the library as getCollateral's answer, and both suites run it through the
// carried-collateral gate at its verify_at.
//
// Run it when attest.MinRootCACRLThisUpdate moves (make record-collateral, after
// building ts): the recording's root CA CRL must be at or after the pin, or the
// gate refuses it. It refuses to write a set the gate would refuse at verify_at.
//
//   node scripts/record-collateral.mjs [pccs-url]   (make record-collateral PCCS=…)

import { readFileSync, writeFileSync } from 'node:fs'
import qvl from '@phala/dcap-qvl'

import {
    EMBEDDED_COLLATERAL_MAX_AGE_MS,
    MIN_ROOT_CA_CRL_THIS_UPDATE_MS,
    collateralFreshEnough,
    crlNextUpdate,
    crlThisUpdate,
} from '../../ts/dist/attest/collateral.js'

const testdata = (p) => new URL(`../../testdata/${p}`, import.meta.url)
const outFile = testdata('attest/ds_collateral.json')
const DAY = 24 * 60 * 60_000

function fail(msg) {
    console.error(`record-collateral: ${msg}`)
    process.exit(1)
}

const pccsUrl = process.argv[2] ?? qvl.PHALA_PCCS_URL
const quote = Buffer.from(readFileSync(testdata('attest/ds_quote_hex.txt'), 'utf8').trim(), 'hex')
// The FMSPC and CA are the quote's, which never changes, so they carry over.
const previous = JSON.parse(readFileSync(outFile, 'utf8'))

const fetched = await qvl.getCollateral(pccsUrl, quote)
const hex = (v) => (typeof v === 'string' ? v : Buffer.from(v).toString('hex'))

// getCollateral falls back to Intel's CRL distribution point, silently, when
// the PCCS rootcacrl route fails. The pin moves only once the mirror serves the
// new CRL, so the recording must be the mirror's own.
const mirrorRoot = await fetch(`${pccsUrl}/sgx/certification/v4/rootcacrl`)
if (!mirrorRoot.ok) fail(`the PCCS rootcacrl route answered HTTP ${mirrorRoot.status}`)
if ((await mirrorRoot.text()).trim().toLowerCase() !== hex(fetched.root_ca_crl).toLowerCase()) {
    fail("getCollateral's root CA CRL is not the one the PCCS serves; it fell back to Intel's")
}
// The wire order, and without pck_certificate_chain, which getCollateral copies
// out of the quote rather than fetching.
const collateral = {
    pck_crl_issuer_chain: fetched.pck_crl_issuer_chain,
    root_ca_crl: hex(fetched.root_ca_crl),
    pck_crl: hex(fetched.pck_crl),
    tcb_info_issuer_chain: fetched.tcb_info_issuer_chain,
    tcb_info: fetched.tcb_info,
    tcb_info_signature: hex(fetched.tcb_info_signature),
    qe_identity_issuer_chain: fetched.qe_identity_issuer_chain,
    qe_identity: fetched.qe_identity,
    qe_identity_signature: hex(fetched.qe_identity_signature),
}
for (const [k, v] of Object.entries(collateral)) {
    if (typeof v !== 'string' || v === '') fail(`getCollateral returned no ${k}`)
}

const ms = (nanos, what) => (nanos === null ? fail(what) : Number(nanos / 1_000_000n))
const tcbIssued = Date.parse(JSON.parse(collateral.tcb_info).issueDate)
const issued = [
    tcbIssued,
    Date.parse(JSON.parse(collateral.qe_identity).issueDate),
    ms(crlThisUpdate(collateral.pck_crl), 'the PCK CRL cannot be dated'),
    ms(crlThisUpdate(collateral.root_ca_crl), 'the root CA CRL cannot be dated'),
]
const expires = [
    Date.parse(JSON.parse(collateral.tcb_info).nextUpdate),
    Date.parse(JSON.parse(collateral.qe_identity).nextUpdate),
    ms(crlNextUpdate(collateral.pck_crl), 'the PCK CRL has no nextUpdate'),
    ms(crlNextUpdate(collateral.root_ca_crl), 'the root CA CRL has no nextUpdate'),
]
if ([...issued, ...expires].some(Number.isNaN)) fail('a document carries no issue or next-update date')
const validFrom = Math.max(...issued)
const validUntil = Math.min(...expires)
// tee-pccs-real.test.ts verifies a day before valid_from and expects the
// library's refusal of a future TCB info, which it checks before the CRLs.
if (tcbIssued <= validFrom - DAY) {
    fail('the TCB info is over a day older than another document, so a check a day before valid_from ' +
        'would not reach its issue date; record again once the PCCS serves a current TCB info')
}
// A UTC midnight a few days in, well inside the 14-day floor and Intel's window.
const verifyAt = Math.floor(validFrom / DAY) * DAY + 5 * DAY
if (verifyAt >= validUntil) fail('the documents expire before verify_at')

// The real-library tests expect the capture's platform UpToDate. Intel can move
// it, and then no recording satisfies them; say so here rather than there.
const { status } = qvl.verify(quote, fetched, Math.floor(verifyAt / 1000))
if (status !== 'UpToDate') {
    fail(`Intel now rates the capture's platform ${status}, and tee-pccs-real.test.ts expects UpToDate; ` +
        'those tests need a new capture or a changed expectation, not a re-record')
}

const root = issued[3]
if (root < MIN_ROOT_CA_CRL_THIS_UPDATE_MS) {
    fail(`the PCCS serves a root CA CRL (${new Date(root).toISOString()}) older than the pin; wait for it to catch up`)
}
if (!collateralFreshEnough(collateral, verifyAt, EMBEDDED_COLLATERAL_MAX_AGE_MS)) {
    fail('the carried-collateral gate refuses this set at verify_at')
}

const version = JSON.parse(readFileSync(new URL('../node_modules/@phala/dcap-qvl/package.json', import.meta.url), 'utf8')).version
const iso = (t) => new Date(t).toISOString().replace('.000Z', 'Z')
const out = {
    source:
        `getCollateral(${pccsUrl}, ds_quote_hex.txt) from @phala/dcap-qvl ${version}, recorded by ` +
        'sdk/scripts/record-collateral.mjs and stored in the TEECollateral wire shape (DER and signatures ' +
        'hex-encoded). Public Intel-signed documents for the capture platform; pck_certificate_chain, which ' +
        'getCollateral copies out of the quote, is omitted.',
    fetched_at: new Date().toISOString().slice(0, 16) + 'Z',
    fmspc: previous.fmspc,
    ca: previous.ca,
    valid_from: iso(validFrom),
    valid_until: iso(validUntil),
    verify_at: iso(verifyAt),
    collateral,
}
writeFileSync(outFile, JSON.stringify(out, null, 2) + '\n')
console.log(`record-collateral: wrote ${outFile.pathname}`)
console.log(`  root CA CRL  ${iso(root)} (pin ${iso(MIN_ROOT_CA_CRL_THIS_UPDATE_MS)})`)
console.log(`  valid        ${out.valid_from} .. ${out.valid_until}, verify_at ${out.verify_at}`)
console.log(`  tcb status   ${status} at verify_at`)
