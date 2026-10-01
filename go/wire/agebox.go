/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// ageSeal and ageOpen are the one-shot age primitive behind every sealed
// envelope in this package: the inner-request frame (WrapRequestWithIdentity),
// the reserve request and response (reserve_seal.go), and the wrapped response
// key (NewResponseSealerWithKey / UnwrapResponseKey).
//
// age gives confidentiality to the recipient, not sender authentication —
// anyone holding a public recipient can seal to it. Admission is proved
// separately by the admission tag (admission.go); a seal alone admits nothing.

func ageSeal(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	if recipient == nil {
		return nil, errors.New("nil age recipient")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age close: %w", err)
	}
	return buf.Bytes(), nil
}

// ageOpen decrypts with the first of identities whose stanza opens the header.
// The variadic order is meaningful — current ephemeral, previous ephemeral
// during the rotation overlap, then any durable fallback.
func ageOpen(ciphertext []byte, identities ...age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("no age identities supplied")
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read age plaintext: %w", err)
	}
	return plaintext, nil
}
