package ed448

import (
	"crypto/hmac"
	"crypto/sha512"
	"github.com/jtejido/spake2plus/internal/suite"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math/big"
)

type Ed448Sha512HkdfHmac struct {
	mhf suite.MHF
}

func (s Ed448Sha512HkdfHmac) Group() suite.Group {
	return curve{}
}

func (s Ed448Sha512HkdfHmac) Hash() hash.Hash {
	return sha512.New()
}

func (s Ed448Sha512HkdfHmac) HashDigest(content []byte) []byte {
	hash := sha512.Sum512(content)
	return hash[:]
}

func (s Ed448Sha512HkdfHmac) HashSize() int {
	return 56
}

func (s Ed448Sha512HkdfHmac) DeriveKey(salt, ikm, info []byte) []byte {
	hkdf := hkdf.New(sha512.New, ikm, salt, info)
	key := make([]byte, 56)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key[:]
}

func (s Ed448Sha512HkdfHmac) Mac(content, secret []byte) []byte {
	mac := hmac.New(sha512.New, secret)
	mac.Write(content)
	hash := mac.Sum(nil)
	return hash[:]
}

func (s Ed448Sha512HkdfHmac) MacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func (s Ed448Sha512HkdfHmac) Mhf(password, salt []byte) ([]byte, error) {
	buf, err := s.mhf(password, salt, 56)
	if err != nil {
		return nil, err
	}

	oversized := new(big.Int)
	oversized.SetBytes(buf)
	return oversized.Mod(oversized, s.Group().Order()).Bytes(), nil
}

func NewEd448Sha512HkdfHmac(mhf suite.MHF) *Ed448Sha512HkdfHmac {
	return &Ed448Sha512HkdfHmac{mhf}
}
