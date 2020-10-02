package ed448

import (
	"errors"
	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/jtejido/spake2plus/internal/suite"
)

type scalar struct {
	v *goldilocks.Scalar
}

func (s *scalar) Bytes() []byte {
	t := *s
	t.v.Red()
	var buf [56]byte
	copy(buf[:], t.v[:])

	return reverse(buf[:])
}

func (s *scalar) FromBytes(buf []byte) error {
	if len(buf) != 56 {
		return errors.New("wrong size buffer")
	}

	b := make([]byte, 56)
	copy(b, buf)
	s.v.FromBytes(reverse(b))
	return nil
}

func (s *scalar) Negate(a suite.Scalar) suite.Scalar {
	t := a.(*scalar)
	*s.v = *t.v
	s.v.Neg()
	return s
}
