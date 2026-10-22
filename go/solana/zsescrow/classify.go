/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"time"

	"github.com/TxnLab/zerosignal/go/settle"
)

// View maps a ticket account onto the rail-neutral view the settlement rules
// read. A status this package doesn't know reads as unrecognized. A deadline
// before the epoch, which no open the program accepts can produce, reads as
// the epoch: long past, rather than wrapping to a deadline that never comes.
func (t *Ticket) View() settle.Ticket {
	var v settle.Ticket
	if d := t.Deadline(); d > 0 {
		v.Deadline = uint64(d)
	}
	switch t.Status {
	case TicketOpen:
		v.Status = settle.StatusOpen
	case TicketPendingByPayer:
		v.Status = settle.StatusPendingPayer
	case TicketPendingByOperator:
		v.Status = settle.StatusPendingOperator
	case TicketFrozen:
		v.Status = settle.StatusFrozen
	}
	return v
}

// Classify reports what can legally happen to t at now, as escrow.Classify
// does for an Algorand box. t must be non-nil: a closed ticket's account is
// gone, and what that means is the caller's to decide.
func Classify(t *Ticket, now time.Time) settle.Verdict {
	return settle.Classify(t.View(), now)
}
