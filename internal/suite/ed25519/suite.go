package ed25519

import (
	"crypto/hmac"
	"crypto/sha256"
	"github.com/jtejido/spake2plus/internal/suite"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math/big"
)

type Ed25519Sha256HkdfHmac struct {
	mhf suite.MHF
}

func (s Ed25519Sha256HkdfHmac) Group() suite.Group {
	return curve{}
}

func (s Ed25519Sha256HkdfHmac) Hash() hash.Hash {
	return sha256.New()
}

func (s Ed25519Sha256HkdfHmac) HashDigest(content []byte) []byte {
	hash := sha256.Sum256(content)
	return hash[:]
}

func (s Ed25519Sha256HkdfHmac) HashSize() int {
	return 32
}

func (s Ed25519Sha256HkdfHmac) DeriveKey(salt, ikm, info []byte) []byte {
	hkdf := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key[:]
}

func (s Ed25519Sha256HkdfHmac) Mac(content, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(content)
	hash := mac.Sum(nil)
	return hash[:]
}

func (s Ed25519Sha256HkdfHmac) MacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func (s Ed25519Sha256HkdfHmac) Mhf(password, salt []byte) ([]byte, error) {
	buf, err := s.mhf(password, salt, 32)
	if err != nil {
		return nil, err
	}

	oversized := new(big.Int)
	oversized.SetBytes(buf)
	return oversized.Mod(oversized, s.Group().Order()).Bytes(), nil
}

func NewEd25519Sha256HkdfHmac(mhf suite.MHF) *Ed25519Sha256HkdfHmac {
	return &Ed25519Sha256HkdfHmac{mhf}
}
