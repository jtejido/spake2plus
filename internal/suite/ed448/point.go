package ed448

import (
	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/jtejido/spake2plus/internal/suite"
)

type point struct {
	p *goldilocks.Point
}

func (P *point) Bytes() []byte {
	b, err := P.p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func (P *point) FromBytes(b []byte) (err error) {
	P.p, err = goldilocks.FromBytes(b)
	return
}

func (P *point) Equal(P2 suite.Element) bool {
	return P.p.IsEqual(P2.(*point).p)
}

func (P *point) Identity() suite.Element {
	c := goldilocks.Curve{}
	P.p = c.Identity()
	return P
}

func (P *point) Add(P1, P2 suite.Element) suite.Element {
	E1 := P1.(*point)
	E2 := P2.(*point)
	tmp := *E1
	tmp.p.Add(E2.p)
	P.p = tmp.p

	return P
}

func (P *point) Negate(A suite.Element) suite.Element {
	a := A.(*point)
	tmp := *a
	tmp.p.Neg()
	P.p = tmp.p
	return P
}

func (P *point) ScalarMult(s suite.Scalar, A suite.Element) suite.Element {
	c := goldilocks.Curve{}
	if A != nil {
		P.p = c.ScalarMult(s.(*scalar).v, A.(*point).p)
	} else {
		P.p = c.ScalarBaseMult(s.(*scalar).v)
	}

	return P
}
