/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command freecreditkey makes a free-credit issuer's master key: the Ed25519
// key that certifies each day's RSA key, and that nodes trust. It writes the
// private key to -out as a PKCS#8 PEM, readable by its owner only, and prints
// the public key (standard base64), which goes into a deployment preset or a
// node's trusted issuers. The private key is never printed, and must sign
// nothing but day-key certificates.
//
//	go run ./cmd/freecreditkey -out issuer.pem
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/TxnLab/zerosignal/go/freecredit"
)

func main() {
	out := flag.String("out", "", "file to write the private key to; must not exist")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "freecreditkey:", err)
		os.Exit(1)
	}
}

func run(out string) (err error) {
	if out == "" {
		return errors.New("-out is required")
	}
	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pemBytes, err := freecredit.MarshalIssuerPEM(sk)
	if err != nil {
		return err
	}
	// O_EXCL: overwriting a live issuer's key would orphan every day key it
	// certified.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		// A partial file would block the retry at the same path.
		if err != nil {
			_ = os.Remove(out)
		}
	}()
	if _, err = f.Write(pemBytes); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Issuer string `json:"issuer"`
	}{base64.StdEncoding.EncodeToString(pub)})
}
