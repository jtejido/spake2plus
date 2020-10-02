package elliptic

import (
	el "crypto/elliptic"
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
	"math/big"
)

type curvePoint struct {
	x, y *big.Int
	c    *curve
}

func (p *curvePoint) Equal(p2 suite.Element) bool {
	cp2 := p2.(*curvePoint)

	M := p.c.p.P
	p.x.Mod(p.x, M)
	p.y.Mod(p.y, M)
	cp2.x.Mod(cp2.x, M)
	cp2.y.Mod(cp2.y, M)

	return p.x.Cmp(cp2.x) == 0 && p.y.Cmp(cp2.y) == 0
}

func (p *curvePoint) Identity() suite.Element {
	p.x = new(big.Int).SetInt64(0)
	p.y = new(big.Int).SetInt64(0)
	return p
}

func (p *curvePoint) valid() bool {
	return p.c.IsOnCurve(p.x, p.y) || (p.x.Sign() == 0 && p.y.Sign() == 0)
}

func (p *curvePoint) Add(a, b suite.Element) suite.Element {
	ca := a.(*curvePoint)
	cb := b.(*curvePoint)
	p.x, p.y = p.c.Add(ca.x, ca.y, cb.x, cb.y)
	return p
}

func (p *curvePoint) ScalarMult(s suite.Scalar, b suite.Element) suite.Element {
	if b != nil {
		cb := b.(*curvePoint)
		p.x, p.y = p.c.ScalarMult(cb.x, cb.y, s.Bytes())
	} else {
		p.x, p.y = p.c.ScalarBaseMult(s.Bytes())
	}
	return p
}

var errInvalidPoint = errors.New("invalid elliptic curve point")

func (p *curvePoint) Bytes() []byte {
	return el.Marshal(p.c, p.x, p.y)
}

func (p *curvePoint) FromBytes(buf []byte) error {
	var c byte
	for _, b := range buf[1:] {
		c |= b
	}

	if c != 0 {
		p.x, p.y = el.Unmarshal(p.c, buf)
		if p.x == nil || !p.valid() {
			return errInvalidPoint
		}
	} else {
		p.x = big.NewInt(0)
		p.y = big.NewInt(0)
	}

	return nil
}

func (p *curvePoint) Negate(a suite.Element) suite.Element {
	s := newScalar(1, p.c.p.N)
	s.Negate(s)
	return p.ScalarMult(s, a).(*curvePoint)
}

// for M & N, directly unmarshalCompress.
func (p *curvePoint) unmarshalCompressed(buf []byte, size int) (x, y *big.Int) {
	if len(buf) != size {
		return nil, nil
	}
	if buf[0] != 2 && buf[0] != 3 { // compressed form
		return nil, nil
	}
	pp := p.c.Params().P
	x = new(big.Int).SetBytes(buf[1:])
	if x.Cmp(pp) >= 0 {
		return nil, nil
	}
	// y² = x³ - 3x + b
	y = polynomial(p.c, x)
	y = y.ModSqrt(y, pp)
	if y == nil {
		return nil, nil
	}
	if byte(y.Bit(0)) != buf[0]&1 {
		y.Neg(y).Mod(y, pp)
	}
	if !p.c.IsOnCurve(x, y) {
		return nil, nil
	}

	return
}

func polynomial(c *curve, x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	x3.Sub(x3, threeX)
	x3.Add(x3, c.Params().B)
	x3.Mod(x3, c.Params().P)

	return x3
}
