/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// Rail names the chain family an escrow deployment runs on. It is the first
// input to DeploymentID so an Algorand and a Solana deployment can never hash
// alike even if their other inputs collide.
type Rail uint8

const (
	RailAlgorand Rail = 1
	RailSolana   Rail = 2
)

// deploymentTag domain-separates the deployment id hash from every signed
// digest in this package.
const deploymentTag = "zs-deployment-v1\x00"

// DeploymentID names one escrow deployment: a rail, the network's genesis
// hash and the escrow's id on that network. The deployment-bound signing
// layouts (ticket v3, receipt v3, reserve v2, ephemeral v2) put it directly
// after their domain tag.
//
// Without it a signature binds only (operator_id, node_id), and those are
// local to one escrow: the same signing key registered on testnet and mainnet,
// or on Algorand and Solana, would sign artifacts valid on both. A verifier
// always compares against its OWN deployment id, never one read off the wire.
//
// The zero value means "not bound" and selects the legacy layouts, which no
// verifier accepts from 9.14 (SPEC § 3a "Deployment binding"); they remain
// defined so their bytes stay pinned. A real id is a SHA-256 output, so it is
// never zero.
type DeploymentID [sha256.Size]byte

// ErrDeploymentMismatch is returned when a signed object names a deployment
// other than the verifier's: a payer and node configured for different
// networks or escrows.
var ErrDeploymentMismatch = errors.New("signed for a different deployment")

// ErrLegacySignature is returned when a signed object carries no deployment id.
var ErrLegacySignature = errors.New("signature is not deployment-bound")

// NewDeploymentID derives the id from its three inputs:
//
//	sha256("zs-deployment-v1\x00" ‖ u8(rail) ‖ genesis_hash[32] ‖ u32be(len(escrow)) ‖ escrow)
func NewDeploymentID(rail Rail, genesisHash []byte, escrow []byte) (DeploymentID, error) {
	if rail != RailAlgorand && rail != RailSolana {
		return DeploymentID{}, fmt.Errorf("deployment id: unknown rail %d", rail)
	}
	if len(genesisHash) != sha256.Size {
		return DeploymentID{}, fmt.Errorf("deployment id: genesis hash is %d bytes, want %d", len(genesisHash), sha256.Size)
	}
	if len(escrow) == 0 {
		return DeploymentID{}, errors.New("deployment id: escrow id is empty")
	}
	b := make([]byte, 0, len(deploymentTag)+1+sha256.Size+4+len(escrow))
	b = append(b, deploymentTag...)
	b = append(b, byte(rail))
	b = append(b, genesisHash...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(escrow)))
	b = append(b, escrow...)
	return sha256.Sum256(b), nil
}

// AlgorandDeploymentID is the id of an escrow application: the escrow input is
// the app id as 8 big-endian bytes.
func AlgorandDeploymentID(genesisHash []byte, appID uint64) (DeploymentID, error) {
	if appID == 0 {
		return DeploymentID{}, errors.New("deployment id: app id is 0")
	}
	return NewDeploymentID(RailAlgorand, genesisHash, binary.BigEndian.AppendUint64(nil, appID))
}

// SolanaDeploymentID is the id of an escrow program: the escrow input is the
// 32-byte program id.
func SolanaDeploymentID(genesisHash []byte, programID []byte) (DeploymentID, error) {
	if len(programID) != 32 {
		return DeploymentID{}, fmt.Errorf("deployment id: program id is %d bytes, want 32", len(programID))
	}
	return NewDeploymentID(RailSolana, genesisHash, programID)
}

// IsZero reports whether d is the unbound value.
func (d DeploymentID) IsZero() bool { return d == DeploymentID{} }

// String is the base64 form used on the wire.
func (d DeploymentID) String() string { return base64.StdEncoding.EncodeToString(d[:]) }

// MarshalText writes base64, matching the other binary fields (ticket_id,
// commit_k). Callers use the `omitzero` tag so an unbound object's JSON is
// byte-identical to a pre-binding one.
func (d DeploymentID) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText refuses anything but exactly 32 bytes of base64, and refuses
// the zero id: on the wire the zero id is spelled by omitting the field, so a
// present all-zero value is malformed rather than a second way to say unbound.
func (d *DeploymentID) UnmarshalText(text []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("decode deployment id: %w", err)
	}
	if len(raw) != len(d) {
		return fmt.Errorf("deployment id is %d bytes, want %d", len(raw), len(d))
	}
	var out DeploymentID
	copy(out[:], raw)
	if out.IsZero() {
		return errors.New("deployment id is all zero")
	}
	*d = out
	return nil
}

// checkDeployment is the shared verifier rule: the object must be bound, and
// to want. An unbound object is refused whatever want is, so a relay that
// strips the binding and lowers proto_version gains nothing.
func checkDeployment(got, want DeploymentID) error {
	if got.IsZero() {
		return ErrLegacySignature
	}
	if want.IsZero() || got != want {
		return ErrDeploymentMismatch
	}
	return nil
}
