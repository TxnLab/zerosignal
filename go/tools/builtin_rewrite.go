/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"fmt"
)

// rewriteBuiltinTools is the shared walk behind RewriteBuiltinToolsChat and
// RewriteBuiltinToolsResponses. The two endpoints differ only in how a
// BuiltinToolDef is marshalled into a function-tool entry — Chat nests it
// under a "function" object, Responses flattens it — so marshalTool is the
// whole difference and the rest is written once.
//
// SPEC.md names both exported wrappers, and the node calls each by name, so
// they keep their signatures; only the bodies collapse.
//
// Tolerance is deliberate and uniform: an empty body, a non-object body, an
// absent "tools", or a "tools" that is not an array all return the body
// unchanged with an empty name map. That matches InjectSafetyIdentifier — a
// malformed body is the upstream's to reject, not this helper's. An entry
// naming a hayai built-in with no matching def IS an error, because the node
// registered a tool it cannot describe.
func rewriteBuiltinTools(
	body []byte,
	defs map[BuiltinToolType]BuiltinToolDef,
	marshalTool func(BuiltinToolDef) (json.RawMessage, error),
) (rewritten []byte, builtinNames map[string]BuiltinToolType, err error) {
	if len(body) == 0 {
		return body, map[string]BuiltinToolType{}, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, map[string]BuiltinToolType{}, nil
	}

	rawTools, ok := obj["tools"]
	if !ok {
		return body, map[string]BuiltinToolType{}, nil
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(rawTools, &arr); err != nil {
		return body, map[string]BuiltinToolType{}, nil
	}

	builtinNames = map[string]BuiltinToolType{}
	changed := false
	for i, entry := range arr {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(entry, &typed); err != nil || !IsBuiltinToolType(typed.Type) {
			continue
		}
		def, ok := defs[BuiltinToolType(typed.Type)]
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s", ErrUnknownBuiltinTool, typed.Type)
		}
		replacement, err := marshalTool(def)
		if err != nil {
			return nil, nil, err
		}
		arr[i] = replacement
		builtinNames[def.Name] = def.Type
		changed = true
	}

	// No hayai built-in in the list: return the ORIGINAL bytes rather than a
	// remarshalled copy, so a body that was never going to change is never
	// reordered or reformatted on its way through.
	if !changed {
		return body, builtinNames, nil
	}

	newTools, err := json.Marshal(arr)
	if err != nil {
		return nil, nil, fmt.Errorf("remarshal tools: %w", err)
	}
	obj["tools"] = newTools
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, builtinNames, nil
}
