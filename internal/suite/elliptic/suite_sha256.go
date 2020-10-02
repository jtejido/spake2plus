package elliptic

import (
	el "crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jtejido/spake2plus/internal/suite"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math/big"
)

type EllipticSha256HkdfHmac struct {
	curve
	mhf suite.MHF
}

func (s EllipticSha256HkdfHmac) Group() suite.Group {
	return s.curve
}

func (s EllipticSha256HkdfHmac) Hash() hash.Hash {
	return sha256.New()
}

func (s EllipticSha256HkdfHmac) HashDigest(content []byte) []byte {
	hash := sha256.Sum256(content)
	return hash[:]
}

func (s EllipticSha256HkdfHmac) HashSize() int {
	return s.curve.ScalarLen()
}

func (s EllipticSha256HkdfHmac) DeriveKey(salt, ikm, info []byte) []byte {
	hkdf := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, s.curve.ScalarLen())
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key[:]
}

func (s EllipticSha256HkdfHmac) Mac(content, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(content)
	hash := mac.Sum(nil)
	return hash[:]
}

func (s EllipticSha256HkdfHmac) MacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func (s EllipticSha256HkdfHmac) Mhf(password, salt []byte) ([]byte, error) {
	buf, err := s.mhf(password, salt, s.ScalarLen())
	if err != nil {
		return nil, err
	}

	// ensure that it is within order, Unmarshalling it to mod.Int won't do it for you.
	oversized := new(big.Int)
	oversized.SetBytes(buf)
	return oversized.Mod(oversized, s.Group().Order()).Bytes(), nil
}

var p256m, p256n, p384m, p384n []byte
var p521m, p521n []byte

func init() {
	p256m, _ = hex.DecodeString("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	p256n, _ = hex.DecodeString("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
	p384m, _ = hex.DecodeString("030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853")
	p384n, _ = hex.DecodeString("02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10")
	p521m, _ = hex.DecodeString("02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa")
	p521n, _ = hex.DecodeString("0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25")
}

func NewP256Sha256HkdfHmac(mhf suite.MHF) *EllipticSha256HkdfHmac {
	suite := new(EllipticSha256HkdfHmac)
	suite.curve.Curve = el.P256()
	suite.curve.p = suite.curve.Params()
	suite.curve.m = p256m
	suite.curve.n = p256n
	suite.mhf = mhf
	return suite
}

// Go's standard P-384 isn't constant time at the time of writing.
func NewP384Sha256HkdfHmac(mhf suite.MHF) *EllipticSha256HkdfHmac {
	suite := new(EllipticSha256HkdfHmac)
	suite.curve.Curve = P384()
	suite.curve.p = suite.curve.Params()
	suite.curve.m = p384m
	suite.curve.n = p384n
	suite.mhf = mhf
	return suite
}
