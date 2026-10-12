/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The Kind a caller branches on for each code is the contract, so it is
// spelled out here rather than read back from errorKinds.
func TestErrorKinds(t *testing.T) {
	want := map[string]Kind{
		"missing_model":                   KindInvalidRequest,
		"bad_image_request":               KindInvalidRequest,
		"bad_image_edit_request":          KindInvalidRequest,
		"max_output_required":             KindInvalidRequest,
		"pin_conflicts_with_continuation": KindInvalidRequest,
		"unsupported_tool":                KindInvalidRequest,
		"context_length_exceeded":         KindContextExceeded,
		"price_ceiling_exceeded":          KindPriceRejected,
		"no_operator":                     KindNoRoute,
		"no_compatible_operator":          KindNoRoute,
		"no_production_operator":          KindNoRoute,
		"no_pinned_operator":              KindNoRoute,
		"no_funded_operator":              KindNoRoute,
		"no_tee_capacity":                 KindNoRoute,
		"no_tool_capacity":                KindNoRoute,
		"no_ephemeral_capacity":           KindNoRoute,
		"no_relay_available":              KindNoRoute,
		"operators_busy":                  KindBusy,
		"operators_unreachable":           KindUnreachable,
		"mbr_pool_exhausted":              KindBusy,
		"canceled":                        KindInterrupted,
		"free_quota_exhausted":            KindFunds,
		"payer_not_opted_in":              KindFunds,
		"wallet_unfunded":                 KindFunds,
		"mbr_pool_underfunded":            KindFunds,
		"spend_cap_exceeded":              KindSpendCap,
		"ticket_price_rejected":           KindOperatorFault,
		"operator_ticket_reuse":           KindOperatorFault,
		"registry":                        KindInternal,
		"tokenize":                        KindInternal,
		"wrap_request":                    KindInternal,
		"wallet_open":                     KindInternal,
		"build_request":                   KindOperatorFault,
		"upstream_unreachable":            KindInterrupted,
		"read_upstream":                   KindInterrupted,
		"response_handler":                KindOperatorFault,
		"stream_setup":                    KindOperatorFault,
		"operator_unsealed_response":      KindOperatorFault,
		"operator_inconsistent_response":  KindOperatorFault,
		"stream_interrupted":              KindInterrupted,
		"upstream_error":                  KindUpstream,
	}
	if len(errorKinds) != len(want) {
		t.Errorf("errorKinds has %d codes, this test pins %d", len(errorKinds), len(want))
	}
	for code, w := range want {
		if got, ok := errorKinds[code]; !ok || got != w {
			t.Errorf("%s: got %q (listed %v), want %q", code, got, ok, w)
		}
	}
	if e := newError("not_a_code", "m"); e.Kind != KindInternal {
		t.Errorf("unlisted code got Kind %q, want internal", e.Kind)
	}
}

// An unlisted code would build a KindInternal error, so a typo or a new site
// that skips the table changes what a caller branches on.
func TestErrorCodesAreListed(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "newError" || len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: newError with a non-literal code; list it in errorKinds and pass the literal", fset.Position(call.Pos()))
				return true
			}
			code, _ := strconv.Unquote(lit.Value)
			if _, ok := errorKinds[code]; !ok {
				t.Errorf("%s: code %q is not in errorKinds", fset.Position(call.Pos()), code)
			}
			seen++
			return true
		})
	}
	if seen < 30 {
		t.Fatalf("found %d newError calls; the scan is looking in the wrong place", seen)
	}
}
