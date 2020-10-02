package ed448

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/jtejido/spake2plus/internal/suite"
	"math/big"
)

var cofactor = new(big.Int).SetInt64(4)
var prime, _ = new(big.Int).SetString("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439", 10)
var primeOrder, _ = new(big.Int).SetString("181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779", 10)

type curve struct {
	goldilocks.Curve
}

func (c curve) String() string {
	return "Ed448"
}

func (c curve) Scalar() suite.Scalar {
	return &scalar{&goldilocks.Scalar{}}
}

func (c curve) Element() suite.Element {
	P := new(point)
	P.p = &goldilocks.Point{}
	return P
}

func (c curve) M() suite.Element {
	pointString, err := hex.DecodeString("b6221038a775ecd007a4e4dde39fd76ae91d3cf0cc92be8f0c2fa6d6b66f9a12942f5a92646109152292464f3e63d354701c7848d9fc3b8880")
	if err != nil {
		panic(err)
	}
	point := c.Element()
	if err := point.FromBytes(pointString); err != nil {
		panic(err)
	}

	return point
}

func (c curve) N() suite.Element {
	pointString, err := hex.DecodeString("6034c65b66e4cd7a49b0edec3e3c9ccc4588afd8cf324e29f0a84a072531c4dbf97ff9af195ed714a689251f08f8e06e2d1f24a0ffc0146600")
	if err != nil {
		panic(err)
	}
	point := c.Element()
	if err := point.FromBytes(pointString); err != nil {
		panic(err)
	}

	return point
}

func (c curve) RandomElement() (suite.Element, error) {
	sc, err := c.RandomScalar()
	return c.Element().ScalarMult(sc, nil), err
}

func (c curve) RandomScalar() (suite.Scalar, error) {
	b := make([]byte, 56)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	randomScalar := goldilocks.Scalar{}
	copy(randomScalar[:], b)
	randomScalar.Red()

	return &scalar{&randomScalar}, nil
}

func (c curve) ScalarLen() int {
	return goldilocks.ScalarSize
}

func (c curve) ElementLen() int {
	return 57
}

func (c curve) Order() *big.Int {
	return primeOrder
}

func (c curve) CofactorScalar() suite.Scalar {
	sc := c.Scalar().(*scalar)
	buf := make([]byte, 56)
	copy(buf[:1], cofactor.Bytes())
	sc.v.FromBytes(reverse(buf))
	return sc
}

func (c curve) ClearCofactor(elem suite.Element) suite.Element {
	return c.Element().ScalarMult(c.CofactorScalar(), elem)
}

func reverse(p []byte) []byte {
	q := make([]byte, len(p))
	for i := 0; 2*i < len(p); i++ {
		j := len(p) - 1 - i
		q[i], q[j] = p[j], p[i]
	}
	return q[:]
}
