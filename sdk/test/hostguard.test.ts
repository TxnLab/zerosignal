/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import { isBlockedOperatorUrl, operatorUrlAllowed } from '../src/index.js'

describe('isBlockedOperatorUrl', () => {
    it.each([
        'http://localhost:8080',
        'https://sub.localhost',
        'http://127.0.0.1:1234',
        'http://127.5.5.5',
        'http://10.0.0.1',
        'http://172.16.0.1',
        'http://172.31.255.255',
        'http://192.168.1.1',
        'http://169.254.1.1',
        'http://100.64.0.1',
        'http://100.127.255.254',
        'http://0.0.0.0',
        'http://224.0.0.1',
        'http://[::1]:8080',
        'http://[fc00::1]',
        'http://[fd12:3456::1]',
        'http://[fe80::1]',
        'http://[febf::1]',
        'http://[ff02::1]',
        'http://[::]',
        // The parser hex-encodes an embedded IPv4, so these block only because
        // the whole of ::/96 does.
        'https://[::ffff:127.0.0.1]/',
        'https://[::ffff:10.0.0.1]/',
        'https://[::127.0.0.1]/',
        'https://[::ffff:8.8.8.8]/',
        'https://localhost./',
        'http://sub.localhost./',
        'http://LOCALHOST',
        'http://printer.local/',
        'http://printer.local./',
        // Shorthand IPv4 spellings the parser rewrites to 127.0.0.1, which is
        // why the guard reads URL.hostname and not the registered string.
        'http://2130706433/',
        'http://0x7f.1/',
        'http://0177.0.0.1/',
        'http://127.1/',
        'http://１２７.0.0.1/',
        'http://240.0.0.1/',
        'http://255.255.255.255/',
        'not a url',
        '',
    ])('blocks %s', (url) => {
        expect(isBlockedOperatorUrl(url)).toBe(true)
    })

    it.each([
        'https://op.example.com',
        'https://8.8.8.8',
        'http://100.63.255.255',
        'http://100.128.0.0',
        'http://172.15.0.1',
        'http://172.32.0.1',
        'http://169.253.255.255',
        'http://192.167.1.1',
        'http://223.255.255.255/',
        'https://[2606:4700:4700::1111]',
        'https://[2001:db8::1]/',
        'https://[fbff::1]/',
        'https://[fec0::1]/',
        'https://node.example.com./',
        'https://localhost.example.com/',
        'https://local.example.com/',
    ])('allows %s', (url) => {
        expect(isBlockedOperatorUrl(url)).toBe(false)
    })
})

describe('operatorUrlAllowed', () => {
    it('allows a private host only with allowPrivateHosts', () => {
        expect(operatorUrlAllowed('http://127.0.0.1:8080', false)).toBe(false)
        expect(operatorUrlAllowed('http://127.0.0.1:8080', true)).toBe(true)
        expect(operatorUrlAllowed('https://op.example', false)).toBe(true)
    })
})
