package ed25519

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/jtejido/spake2plus/internal/suite"
	"math/big"
)

var cofactor = new(big.Int).SetInt64(8)
var prime, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
var primeOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

type curve struct {
}

func (c curve) String() string {
	return "Ed25519"
}

func (c curve) Scalar() suite.Scalar {
	return &scalar{}
}

func (c curve) Element() suite.Element {
	P := new(point)
	return P
}

func (c curve) M() suite.Element {
	str, err := hex.DecodeString("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
	if err != nil {
		panic(err)
	}
	point := c.Element()
	if err := point.FromBytes(str); err != nil {
		panic(err)
	}

	return point
}

func (c curve) N() suite.Element {
	str, err := hex.DecodeString("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")
	if err != nil {
		panic(err)
	}
	point := c.Element()
	if err := point.FromBytes(str); err != nil {
		panic(err)
	}

	return point
}

func (c curve) RandomElement() (suite.Element, error) {
	sc, err := c.RandomScalar()
	return c.Element().ScalarMult(sc, nil), err
}

func (c curve) RandomScalar() (suite.Scalar, error) {
	var b [64]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return nil, err
	}

	var randomScalar scalar

	// reduce to mod order
	scReduce(&randomScalar, &b)
	return &randomScalar, nil
}

func (c curve) ScalarLen() int {
	return 32
}

func (c curve) ElementLen() int {
	return 32
}

func (c curve) Order() *big.Int {
	return primeOrder
}

func (c curve) CofactorScalar() suite.Scalar {
	var sc scalar
	buf := make([]byte, 32)
	copy(buf[:1], cofactor.Bytes())
	copy(sc[:], reverse(buf))
	return &sc
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
