package elliptic

import (
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
	"math/big"
)

type scalar struct {
	v big.Int
	m *big.Int
}

func newScalar(v int64, m *big.Int) *scalar {
	return new(scalar).init(v, m)
}

func newScalarFromBytes(a []byte, m *big.Int) *scalar {
	return new(scalar).initBytes(a, m)
}

func (i *scalar) init(v int64, m *big.Int) *scalar {
	i.m = m
	i.v.SetInt64(v).Mod(&i.v, m)
	return i
}

func (i *scalar) initBytes(a []byte, m *big.Int) *scalar {
	i.m = m
	var buff = a
	i.v.SetBytes(buff).Mod(&i.v, i.m)
	return i
}

func (i *scalar) Bytes() []byte {
	l := (i.m.BitLen() + 7) / 8
	b := i.v.Bytes()
	offset := l - len(b)

	if offset != 0 {
		nb := make([]byte, l)
		copy(nb[offset:], b)
		b = nb
	}

	return b
}

func (i *scalar) FromBytes(buf []byte) error {
	l := (i.m.BitLen() + 7) / 8
	if len(buf) != l {
		return errors.New("wrong size buffer")
	}

	i.v.SetBytes(buf)
	if i.v.Cmp(i.m) >= 0 {
		return errors.New("value out of range")
	}
	return nil
}

func (i *scalar) Negate(a suite.Scalar) suite.Scalar {
	ai := a.(*scalar)
	i.m = ai.m
	if ai.v.Sign() > 0 {
		i.v.Sub(i.m, &ai.v)
	} else {
		i.v.SetUint64(0)
	}
	return i
}
