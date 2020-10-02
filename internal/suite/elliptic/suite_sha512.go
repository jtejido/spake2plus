package elliptic

import (
	el "crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"github.com/jtejido/spake2plus/internal/suite"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math/big"
)

type EllipticSha512HkdfHmac struct {
	curve
	mhf suite.MHF
}

func (s EllipticSha512HkdfHmac) Group() suite.Group {
	return s.curve
}

func (s EllipticSha512HkdfHmac) Hash() hash.Hash {
	return sha512.New()
}

func (s EllipticSha512HkdfHmac) HashDigest(content []byte) []byte {
	hash := sha512.Sum512(content)
	return hash[:]
}

func (s EllipticSha512HkdfHmac) HashSize() int {
	return s.curve.ScalarLen()
}

func (s EllipticSha512HkdfHmac) DeriveKey(salt, ikm, info []byte) []byte {
	hkdf := hkdf.New(sha512.New, ikm, salt, info)
	key := make([]byte, s.curve.ScalarLen())
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key[:]
}

func (s EllipticSha512HkdfHmac) Mac(content, secret []byte) []byte {
	mac := hmac.New(sha512.New, secret)
	mac.Write(content)
	hash := mac.Sum(nil)
	return hash[:]
}

func (s EllipticSha512HkdfHmac) MacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func (s EllipticSha512HkdfHmac) Mhf(password, salt []byte) ([]byte, error) {
	buf, err := s.mhf(password, salt, s.ScalarLen())
	if err != nil {
		return nil, err
	}

	// ensure that it is within order
	oversized := new(big.Int)
	oversized.SetBytes(buf)
	return oversized.Mod(oversized, s.Group().Order()).Bytes(), nil
}

func NewP256Sha512HkdfHmac(mhf suite.MHF) *EllipticSha512HkdfHmac {
	suite := new(EllipticSha512HkdfHmac)
	suite.curve.Curve = el.P256()
	suite.curve.p = suite.curve.Params()
	suite.curve.m = p256m
	suite.curve.n = p256n
	suite.mhf = mhf
	return suite
}

// Go's standard P-384 isn't constant time at the time of writing.
func NewP384Sha512HkdfHmac(mhf suite.MHF) *EllipticSha512HkdfHmac {
	suite := new(EllipticSha512HkdfHmac)
	suite.curve.Curve = P384()
	suite.curve.p = suite.curve.Params()
	suite.curve.m = p384m
	suite.curve.n = p384n
	suite.mhf = mhf
	return suite
}

func NewP521Sha512HkdfHmac(mhf suite.MHF) *EllipticSha512HkdfHmac {
	suite := new(EllipticSha512HkdfHmac)
	suite.curve.Curve = el.P521()
	suite.curve.p = suite.curve.Params()
	suite.curve.m = p521m
	suite.curve.n = p521n
	suite.mhf = mhf
	return suite
}
