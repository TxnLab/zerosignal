/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command rootcrlpin reports whether attest.MinRootCACRLThisUpdate is still
// the thisUpdate of Intel's current root CA CRL, and whether the mirror that
// nodes use by default serves that CRL.
//
//	go run ./cmd/rootcrlpin
//
// Exit 0: the pin is current. Exit 1, with the action on the last line: Intel
// has published a newer root CA CRL (bump the pin, once the mirror serves it);
// the pin names a CRL newer than Intel's; the mirror serves one older than the
// pin; or Intel's CRL is near or past its nextUpdate. Each of the last three
// refuses every honest carried set. Exit 2: Intel's CRL could not be read.
//
// Nothing verifies a CRL's signature here: this only decides when a human
// looks, and the pin it prompts is checked against Intel-signed bytes by the
// verifier that uses it.
package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/attest"
)

const (
	// The CRL distribution point in Intel's SGX root CA certificate. Intel's
	// PCS has no rootcacrl route; a PCCS serves one, hex-encoded.
	intelURL  = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
	mirrorURL = "https://pccs.phala.network/sgx/certification/v4/rootcacrl"
)

func main() {
	os.Exit(run(os.Stdout))
}

// expiryWarning is how far ahead of Intel's nextUpdate a missing successor is
// reported. Past it every carried set is refused whatever the pin says.
const expiryWarning = 30 * 24 * time.Hour

func run(w io.Writer) int {
	pin := attest.MinRootCACRLThisUpdate()
	fmt.Fprintf(w, "pin     %s\n", pin.Format(time.RFC3339))

	intel, err := fetchCRL(intelURL, false)
	if err != nil {
		fmt.Fprintf(w, "intel   unreadable: %v\n", err)
		return 2
	}
	fmt.Fprintf(w, "intel   %s (nextUpdate %s)\n", intel.ThisUpdate.Format(time.RFC3339), intel.NextUpdate.Format(time.RFC3339))

	// An unreadable mirror is reported and does not change the verdict: it
	// only decides whether a bump can ship yet.
	mirror, merr := fetchCRL(mirrorURL, true)
	if merr != nil {
		fmt.Fprintf(w, "mirror  unreadable: %v\n", merr)
	} else {
		fmt.Fprintf(w, "mirror  %s\n", mirror.ThisUpdate.Format(time.RFC3339))
	}

	var mirrorAt *time.Time
	if merr == nil {
		mirrorAt = &mirror.ThisUpdate
	}
	msg, code := verdict(pin, intel.ThisUpdate, intel.NextUpdate, mirrorAt, time.Now())
	fmt.Fprintln(w, msg)
	return code
}

// verdict is the action for one reading; mirror is nil when it was unreadable.
// The order matters: each case above "ok" refuses every honest carried set
// even while the pin equals Intel's CRL.
func verdict(pin, intel, intelNext time.Time, mirror *time.Time, now time.Time) (string, int) {
	switch {
	case intel.Before(pin):
		return "fix the pin: it is newer than Intel's root CA CRL, so every carried set is refused", 1
	case mirror != nil && mirror.Before(pin):
		return "the mirror serves a root CA CRL older than the pin, so nodes carrying it are refused; " +
			"report it to Phala, or move the pin back if it was bumped too early", 1
	case intel.Equal(pin) && now.After(intelNext.Add(-expiryWarning)):
		return fmt.Sprintf("Intel's root CA CRL reaches its nextUpdate %s with no successor published; "+
			"past it every carried set is refused", intelNext.Format(time.RFC3339)), 1
	case intel.Equal(pin):
		return "ok: the pin is Intel's current root CA CRL", 0
	case mirror != nil && mirror.Equal(intel):
		return "bump: Intel published a newer root CA CRL and the mirror serves it; " +
			"move the pin to Intel's thisUpdate and re-record (make record-collateral)", 1
	default:
		return "bump pending: Intel published a newer root CA CRL; " +
			"move the pin once the mirror serves it, since nodes carry what their PCCS serves", 1
	}
}

func fetchCRL(url string, hexBody bool) (*x509.RevocationList, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if hexBody {
		if body, err = hex.DecodeString(strings.TrimSpace(string(body))); err != nil {
			return nil, fmt.Errorf("not hex: %w", err)
		}
	}
	return x509.ParseRevocationList(body)
}
