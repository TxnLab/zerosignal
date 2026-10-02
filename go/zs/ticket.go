/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"fmt"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// NodeRef addresses one node: the (operator id, node id) pair every routing
// store keys by. Operator id alone is correct only for owner-level concerns
// (payout, relay owner diversity), because one operator runs many nodes with
// independent health and continuation state.
type NodeRef struct {
	Op   uint64
	Node uint64
}

func (r NodeRef) String() string { return fmt.Sprintf("%d/%d", r.Op, r.Node) }

// Ticket is one paid reservation and its open escrow box: the only handle
// that can move that ticket's money. A Stream drives it to settle, protest or
// refund on its own; it is exported so an integrator can reconcile a ticket
// the process lost track of.
type Ticket struct {
	// ID is the base64 ticket id, as carried in the envelope.
	ID string
	// Signed is the operator-signed ticket the reservation returned.
	Signed ticket.Ticket
	// Target is the node that issued it and that the escrow pays.
	Target NodeRef
}
