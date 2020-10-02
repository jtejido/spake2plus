package spake2plus

import (
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
	"github.com/jtejido/spake2plus/internal/suite/ed25519"
	"github.com/jtejido/spake2plus/internal/suite/ed448"
	"github.com/jtejido/spake2plus/internal/suite/elliptic"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

func Ed25519Sha256HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return ed25519.NewEd25519Sha256HkdfHmac(mhf)
}

func Ed448Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return ed448.NewEd448Sha512HkdfHmac(mhf)
}

func P256Sha256HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP256Sha256HkdfHmac(mhf)
}

func P384Sha256HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP384Sha256HkdfHmac(mhf)
}

func P256Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP256Sha512HkdfHmac(mhf)
}

func P384Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP384Sha512HkdfHmac(mhf)
}

func P521Sha512HkdfHmac(mhf suite.MHF) suite.CipherSuite {
	return elliptic.NewP521Sha512HkdfHmac(mhf)
}

// Confirmations provides a easy interface for confirmation verification, for state load.
type Confirmations struct {
	confirmation       []byte
	remoteConfirmation []byte
	suite              suite.CipherSuite
}

// NewConfirmations creates a Confirmations.
func NewConfirmations(confirmation, remoteConfirmation []byte, suite suite.CipherSuite) *Confirmations {
	return &Confirmations{confirmation, remoteConfirmation, suite}
}

// Bytes gets the confirmation message.
func (c Confirmations) Bytes() []byte {
	return c.confirmation
}

// Verify verifies an incoming confirmation message.
func (c Confirmations) Verify(incomingConfirmation []byte) error {
	if !c.suite.MacEqual(incomingConfirmation, c.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}

// MHFs
func Scrypt(N, r, p int) suite.MHF {
	return func(password, salt []byte, len int) ([]byte, error) {
		return scrypt.Key(password, salt, N, r, p, len)
	}
}

func Argon2(time, memory uint32, threads uint8) suite.MHF {
	return func(password, salt []byte, len int) ([]byte, error) {
		return argon2.Key(password, salt, time, memory, threads, uint32(len)), nil
	}
}
