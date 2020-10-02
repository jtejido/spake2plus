package elliptic

import (
	el "crypto/elliptic"
	"crypto/rand"
	"github.com/jtejido/spake2plus/internal/suite"
	"math/big"
)

type curve struct {
	el.Curve
	n, m []byte
	p    *el.CurveParams
}

func (c curve) String() string {
	return c.p.Name
}

func (c curve) ScalarLen() int { return (c.p.N.BitLen() + 7) / 8 }

func (c curve) Scalar() suite.Scalar {
	return newScalar(0, c.p.N)
}

func (c curve) coordLen() int {
	return (c.p.BitSize + 7) / 8
}

func (c curve) ElementLen() int {
	return 1 + 2*c.coordLen()
}

func (c curve) Element() suite.Element {
	p := new(curvePoint)
	p.c = &c
	return p
}

// TO-DO: 5.  Per-User M and N in SPAKE2 RFC
func (c curve) M() suite.Element {
	point := c.Element().(*curvePoint)
	var ch byte
	for _, b := range c.n[1:] {
		ch |= b
	}
	if ch != 0 {
		point.x, point.y = point.unmarshalCompressed(c.n, 1+c.coordLen())
		if point.x == nil || !point.valid() {
			panic("invalid elliptic curve point")
		}
	} else {
		point.x = big.NewInt(0)
		point.y = big.NewInt(0)
	}

	return point

}

// TO-DO: 5.  Per-User M and N in SPAKE2 RFC
func (c curve) N() suite.Element {
	point := c.Element().(*curvePoint)
	var ch byte
	for _, b := range c.n[1:] {
		ch |= b
	}
	if ch != 0 {
		point.x, point.y = point.unmarshalCompressed(c.n, 1+c.coordLen())
		if point.x == nil || !point.valid() {
			panic("invalid elliptic curve point")
		}
	} else {
		point.x = big.NewInt(0)
		point.y = big.NewInt(0)
	}

	return point

}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

func (c curve) RandomElement() (suite.Element, error) {
	sc, err := c.RandomScalar()
	return c.Element().ScalarMult(sc, nil), err
}

func (c curve) RandomScalar() (suite.Scalar, error) {
	buf := make([]byte, c.ScalarLen())
	bitLen := c.p.N.BitLen()

	for {
		_, err := rand.Read(buf)
		if err != nil {
			return nil, err
		}
		buf[0] &= mask[bitLen%8]
		buf[1] ^= 0x42
		if new(big.Int).SetBytes(buf).Cmp(c.Order()) < 0 {
			break
		}
	}

	sc := c.Scalar()
	err := sc.FromBytes(buf)
	return sc, err
}

func (c curve) Order() *big.Int {
	return c.p.N
}

func (c curve) CofactorScalar() suite.Scalar {
	return newScalar(1, c.p.N)
}

func (c curve) ClearCofactor(elem suite.Element) suite.Element {
	return c.Element().ScalarMult(c.CofactorScalar(), elem)
}
