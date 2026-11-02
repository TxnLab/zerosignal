/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// checkLocalChain refuses a Config whose Local defaults loosened Privacy or
// AllowPrivateHosts when the chain behind its loopback endpoint is a public
// one: through a tunnel or a forwarder, discovery would list that chain's
// operators, and the payer would show them its address and dial whatever
// private URL one registered. A read that fails fails the check, since the
// defaults were loosened on the assumption it would pass. Set values were
// the caller's choice and are not checked.
func checkLocalChain(ctx context.Context, cfg Config, rail ticket.Rail, genesis func(context.Context) ([]byte, error)) error {
	if !cfg.localDefaults {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, escrowConfigTimeout)
	defer cancel()
	g, err := genesis(rctx)
	if err != nil {
		return fmt.Errorf("zs: read genesis hash: %w", err)
	}
	if name := PublicChain(rail, g); name != "" {
		return configError(fmt.Sprintf("the localnet endpoint serves %s; name that network, or set Privacy and AllowPrivateHosts", name))
	}
	return nil
}
