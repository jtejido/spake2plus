package ed25519

import (
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
	ed "github.com/jtejido/spake2plus/internal/suite/ed25519/internal/ed25519"
)

type point struct {
	ge ed.ExtendedGroupElement
}

func (P *point) Bytes() []byte {
	var b [32]byte
	P.ge.ToBytes(&b)
	return b[:]
}

func (P *point) FromBytes(b []byte) error {
	if !P.ge.FromBytes(b) {
		return errors.New("invalid Ed25519 curve point")
	}
	return nil
}

func (P *point) Equal(P2 suite.Element) bool {
	var b1, b2 [32]byte
	P.ge.ToBytes(&b1)
	P2.(*point).ge.ToBytes(&b2)
	for i := range b1 {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func (P *point) Identity() suite.Element {
	P.ge.Zero()
	return P
}

func (P *point) Add(P1, P2 suite.Element) suite.Element {
	E1 := P1.(*point)
	E2 := P2.(*point)

	var t2 ed.CachedGroupElement
	var r ed.CompletedGroupElement

	E2.ge.ToCached(&t2)
	r.Add(&E1.ge, &t2)
	r.ToExtended(&P.ge)

	return P
}

func (P *point) Negate(A suite.Element) suite.Element {
	P.ge.Neg(&A.(*point).ge)
	return P
}

func (P *point) ScalarMult(s suite.Scalar, A suite.Element) suite.Element {
	a := s.(*scalar)
	var tmp [32]byte
	copy(tmp[:], a[:])
	if A == nil {
		ed.GeScalarMultBase(&P.ge, &tmp)
	} else {
		ed.GeScalarMult(&P.ge, &tmp, &A.(*point).ge)
	}

	return P
}
