package spake2plus

import (
	"bytes"
	"encoding/hex"
)

type Verifier struct {
	// identity with a verifier. To be stored on a non-volatile DB.
	I        []byte
	Verifier VerifierPair
}

type VerifierPair struct {
	V1, V2 []byte
}

// Encode the verifier into a portable format - returns a tuple
// <Identity, VerifierPair> as portable strings. The caller can store
// the Verifier against the Identity in non-volatile storage.
// An SRP client will supply Identity and its public key - whereupon,
// an SRP server will use the Identity as a key to lookup
// the rest of the encoded verifier data.
func (v *Verifier) Encode() (string, string) {
	var b bytes.Buffer

	ih := hex.EncodeToString(v.I)
	b.WriteString(ih)
	b.WriteByte(':')
	b.WriteString(hex.EncodeToString(v.Verifier.V1))
	b.WriteString(hex.EncodeToString(v.Verifier.V2))
	return ih, b.String()
}

// ServerMaterial is what you send out to the client A so it can verify the confirmation against the given B and secret key known only to A.
// SPAKE2+ reference says that we can send it all in one go. This saves an extra round.
type ServerMaterial struct {
	B []byte
}
