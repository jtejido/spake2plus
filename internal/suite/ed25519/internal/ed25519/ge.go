// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ed25519

// Group elements are members of the elliptic curve -x^2 + y^2 = 1 + d * x^2 *
// y^2 where d = -121665/121666.
//
// Several representations are used:
//   ProjectiveGroupElement: (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ExtendedGroupElement: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   CompletedGroupElement: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   PreComputedGroupElement: (y+x,y-x,2dxy)

type ProjectiveGroupElement struct {
	X, Y, Z FieldElement
}

type ExtendedGroupElement struct {
	X, Y, Z, T FieldElement
}

type CompletedGroupElement struct {
	X, Y, Z, T FieldElement
}

type PreComputedGroupElement struct {
	yPlusX, yMinusX, xy2d FieldElement
}

type CachedGroupElement struct {
	yPlusX, yMinusX, Z, T2d FieldElement
}

func G() *ExtendedGroupElement {
	g := new(ExtendedGroupElement)
	var f FieldElement
	FeOne(&f)
	var s [32]byte
	FeToBytes(&s, &f)
	GeScalarMultBase(g, &s) // g = g^1
	return g
}

func (p *ProjectiveGroupElement) Zero() {
	FeZero(&p.X)
	FeOne(&p.Y)
	FeOne(&p.Z)
}

func (p *ProjectiveGroupElement) Double(r *CompletedGroupElement) {
	var t0 FieldElement

	FeSquare(&r.X, &p.X)
	FeSquare(&r.Z, &p.Y)
	FeSquare2(&r.T, &p.Z)
	FeAdd(&r.Y, &p.X, &p.Y)
	FeSquare(&t0, &r.Y)
	FeAdd(&r.Y, &r.Z, &r.X)
	FeSub(&r.Z, &r.Z, &r.X)
	FeSub(&r.X, &t0, &r.Y)
	FeSub(&r.T, &r.T, &r.Z)
}

func (p *ProjectiveGroupElement) ToBytes(s *[32]byte) {
	var recip, x, y FieldElement

	FeInvert(&recip, &p.Z)
	FeMul(&x, &p.X, &recip)
	FeMul(&y, &p.Y, &recip)
	FeToBytes(s, &y)
	s[31] ^= FeIsNegative(&x) << 7
}

func (p *ExtendedGroupElement) Zero() {
	FeZero(&p.X)
	FeOne(&p.Y)
	FeOne(&p.Z)
	FeZero(&p.T)
}

func (p *ExtendedGroupElement) Neg(s *ExtendedGroupElement) {
	FeNeg(&p.X, &s.X)
	FeCopy(&p.Y, &s.Y)
	FeCopy(&p.Z, &s.Z)
	FeNeg(&p.T, &s.T)
}

func (p *ExtendedGroupElement) Double(r *CompletedGroupElement) {
	var q ProjectiveGroupElement
	p.ToProjective(&q)
	q.Double(r)
}

func (p *ExtendedGroupElement) ToCached(r *CachedGroupElement) {
	FeAdd(&r.yPlusX, &p.Y, &p.X)
	FeSub(&r.yMinusX, &p.Y, &p.X)
	FeCopy(&r.Z, &p.Z)
	FeMul(&r.T2d, &p.T, &d2)
}

func (p *ExtendedGroupElement) ToProjective(r *ProjectiveGroupElement) {
	FeCopy(&r.X, &p.X)
	FeCopy(&r.Y, &p.Y)
	FeCopy(&r.Z, &p.Z)
}

func (p *ExtendedGroupElement) ToBytes(s *[32]byte) {
	var recip, x, y FieldElement

	FeInvert(&recip, &p.Z)
	FeMul(&x, &p.X, &recip)
	FeMul(&y, &p.Y, &recip)
	FeToBytes(s, &y)
	s[31] ^= FeIsNegative(&x) << 7
}

func (p *ExtendedGroupElement) FromBytes(s []byte) bool {
	var u, v, v3, vxx, check FieldElement

	if len(s) != 32 {
		return false
	}
	FeFromBytes(&p.Y, s)
	FeOne(&p.Z)
	FeSquare(&u, &p.Y)
	FeMul(&v, &u, &d)
	FeSub(&u, &u, &p.Z) // y = y^2-1
	FeAdd(&v, &v, &p.Z) // v = dy^2+1

	FeSquare(&v3, &v)
	FeMul(&v3, &v3, &v) // v3 = v^3
	FeSquare(&p.X, &v3)
	FeMul(&p.X, &p.X, &v)
	FeMul(&p.X, &p.X, &u) // x = uv^7

	fePow22523(&p.X, &p.X) // x = (uv^7)^((q-5)/8)
	FeMul(&p.X, &p.X, &v3)
	FeMul(&p.X, &p.X, &u) // x = uv^3(uv^7)^((q-5)/8)

	FeSquare(&vxx, &p.X)
	FeMul(&vxx, &vxx, &v)
	FeSub(&check, &vxx, &u) // vx^2-u
	if FeIsNonZero(&check) == 1 {
		FeAdd(&check, &vxx, &u) // vx^2+u
		if FeIsNonZero(&check) == 1 {
			return false
		}
		FeMul(&p.X, &p.X, &sqrtM1)
	}

	if FeIsNegative(&p.X) != (s[31] >> 7) {
		FeNeg(&p.X, &p.X)
	}

	FeMul(&p.T, &p.X, &p.Y)
	return true
}

func (p *ExtendedGroupElement) String() string {
	return "ExtendedGroupElement{\n\t" +
		p.X.String() + ",\n\t" +
		p.Y.String() + ",\n\t" +
		p.Z.String() + ",\n\t" +
		p.T.String() + ",\n}"
}

// CompletedGroupElement methods

func (c *CompletedGroupElement) ToProjective(r *ProjectiveGroupElement) {
	FeMul(&r.X, &c.X, &c.T)
	FeMul(&r.Y, &c.Y, &c.Z)
	FeMul(&r.Z, &c.Z, &c.T)
}

func (c *CompletedGroupElement) ToExtended(r *ExtendedGroupElement) {
	FeMul(&r.X, &c.X, &c.T)
	FeMul(&r.Y, &c.Y, &c.Z)
	FeMul(&r.Z, &c.Z, &c.T)
	FeMul(&r.T, &c.X, &c.Y)
}

func (p *PreComputedGroupElement) Zero() {
	FeOne(&p.yPlusX)
	FeOne(&p.yMinusX)
	FeZero(&p.xy2d)
}

// geAdd
func (c *CompletedGroupElement) Add(p *ExtendedGroupElement, q *CachedGroupElement) {
	var t0 FieldElement

	FeAdd(&c.X, &p.Y, &p.X)
	FeSub(&c.Y, &p.Y, &p.X)
	FeMul(&c.Z, &c.X, &q.yPlusX)
	FeMul(&c.Y, &c.Y, &q.yMinusX)
	FeMul(&c.T, &q.T2d, &p.T)
	FeMul(&c.X, &p.Z, &q.Z)
	FeAdd(&t0, &c.X, &c.X)
	FeSub(&c.X, &c.Z, &c.Y)
	FeAdd(&c.Y, &c.Z, &c.Y)
	FeAdd(&c.Z, &t0, &c.T)
	FeSub(&c.T, &t0, &c.T)
}

// geSub
func (c *CompletedGroupElement) Sub(p *ExtendedGroupElement, q *CachedGroupElement) {
	var t0 FieldElement

	FeAdd(&c.X, &p.Y, &p.X)
	FeSub(&c.Y, &p.Y, &p.X)
	FeMul(&c.Z, &c.X, &q.yMinusX)
	FeMul(&c.Y, &c.Y, &q.yPlusX)
	FeMul(&c.T, &q.T2d, &p.T)
	FeMul(&c.X, &p.Z, &q.Z)
	FeAdd(&t0, &c.X, &c.X)
	FeSub(&c.X, &c.Z, &c.Y)
	FeAdd(&c.Y, &c.Z, &c.Y)
	FeSub(&c.Z, &t0, &c.T)
	FeAdd(&c.T, &t0, &c.T)
}

func (c *CompletedGroupElement) MixedAdd(p *ExtendedGroupElement, q *PreComputedGroupElement) {
	var t0 FieldElement

	FeAdd(&c.X, &p.Y, &p.X)
	FeSub(&c.Y, &p.Y, &p.X)
	FeMul(&c.Z, &c.X, &q.yPlusX)
	FeMul(&c.Y, &c.Y, &q.yMinusX)
	FeMul(&c.T, &q.xy2d, &p.T)
	FeAdd(&t0, &p.Z, &p.Z)
	FeSub(&c.X, &c.Z, &c.Y)
	FeAdd(&c.Y, &c.Z, &c.Y)
	FeAdd(&c.Z, &t0, &c.T)
	FeSub(&c.T, &t0, &c.T)
}

func (c *CompletedGroupElement) MixedSub(p *ExtendedGroupElement, q *PreComputedGroupElement) {
	var t0 FieldElement

	FeAdd(&c.X, &p.Y, &p.X)
	FeSub(&c.Y, &p.Y, &p.X)
	FeMul(&c.Z, &c.X, &q.yMinusX)
	FeMul(&c.Y, &c.Y, &q.yPlusX)
	FeMul(&c.T, &q.xy2d, &p.T)
	FeAdd(&t0, &p.Z, &p.Z)
	FeSub(&c.X, &c.Z, &c.Y)
	FeAdd(&c.Y, &c.Z, &c.Y)
	FeSub(&c.Z, &t0, &c.T)
	FeAdd(&c.T, &t0, &c.T)
}

// PreComputedGroupElement methods

// Set to u conditionally based on b
func (p *PreComputedGroupElement) CMove(u *PreComputedGroupElement, b int32) {
	FeCMove(&p.yPlusX, &u.yPlusX, b)
	FeCMove(&p.yMinusX, &u.yMinusX, b)
	FeCMove(&p.xy2d, &u.xy2d, b)
}

// Set to negative of t
func (p *PreComputedGroupElement) Neg(t *PreComputedGroupElement) {
	FeCopy(&p.yPlusX, &t.yMinusX)
	FeCopy(&p.yMinusX, &t.yPlusX)
	FeNeg(&p.xy2d, &t.xy2d)
}

// CachedGroupElement methods

func (r *CachedGroupElement) Zero() {
	FeOne(&r.yPlusX)
	FeOne(&r.yMinusX)
	FeOne(&r.Z)
	FeZero(&r.T2d)
}

// Set to u conditionally based on b
func (r *CachedGroupElement) CMove(u *CachedGroupElement, b int32) {
	FeCMove(&r.yPlusX, &u.yPlusX, b)
	FeCMove(&r.yMinusX, &u.yMinusX, b)
	FeCMove(&r.Z, &u.Z, b)
	FeCMove(&r.T2d, &u.T2d, b)
}

// Set to negative of t
func (r *CachedGroupElement) Neg(t *CachedGroupElement) {
	FeCopy(&r.yPlusX, &t.yMinusX)
	FeCopy(&r.yMinusX, &t.yPlusX)
	FeCopy(&r.Z, &t.Z)
	FeNeg(&r.T2d, &t.T2d)
}

// Expand the 32-byte (256-bit) exponent in slice a into
// a sequence of 256 multipliers, one per exponent bit position.
// Clumps nearby 1 bits into multi-bit multipliers to reduce
// the total number of add/sub operations in a point multiply;
// each multiplier is either zero or an odd number between -15 and 15.
// Assumes the target array r has been preinitialized with zeros
// in case the input slice a is less than 32 bytes.
func slide(r *[256]int8, a *[32]byte) {

	// Explode the exponent a into a little-endian array, one bit per byte
	for i := range a {
		ai := int8(a[i])
		for j := 0; j < 8; j++ {
			r[i*8+j] = ai & 1
			ai >>= 1
		}
	}

	// Go through and clump sequences of 1-bits together wherever possible,
	// while keeping r[i] in the range -15 through 15.
	// Note that each nonzero r[i] in the result will always be odd,
	// because clumping is triggered by the first, least-significant,
	// 1-bit encountered in a clump, and that first bit always remains 1.
	for i := range r {
		if r[i] != 0 {
			for b := 1; b <= 6 && i+b < 256; b++ {
				if r[i+b] != 0 {
					if r[i]+(r[i+b]<<uint(b)) <= 15 {
						r[i] += r[i+b] << uint(b)
						r[i+b] = 0
					} else if r[i]-(r[i+b]<<uint(b)) >= -15 {
						r[i] -= r[i+b] << uint(b)
						for k := i + b; k < 256; k++ {
							if r[k] == 0 {
								r[k] = 1
								break
							}
							r[k] = 0
						}
					} else {
						break
					}
				}
			}
		}
	}
}

// equal returns 1 if b == c and 0 otherwise.
func equal(b, c int32) int32 {
	x := uint32(b ^ c)
	x--
	return int32(x >> 31)
}

// negative returns 1 if b < 0 and 0 otherwise.
func negative(b int32) int32 {
	return (b >> 31) & 1
}

func selectPreComputed(t *PreComputedGroupElement, pos int32, b int32) {
	var minusT PreComputedGroupElement
	bNegative := negative(b)
	bAbs := b - (((-bNegative) & b) << 1)

	t.Zero()
	for i := int32(0); i < 8; i++ {
		t.CMove(&base[pos][i], equal(bAbs, i+1))
	}
	minusT.Neg(t)
	t.CMove(&minusT, bNegative)
}

func computeScalarWindow4(s *[32]byte, w *[64]int8) {
	for i := 0; i < 32; i++ {
		w[2*i] = int8(s[i] & 15)
		w[2*i+1] = int8((s[i] >> 4) & 15)
	}
	carry := int8(0)
	for i := 0; i < 63; i++ {
		w[i] += carry
		carry = (w[i] + 8) >> 4
		w[i] -= carry << 4
	}
	w[63] += carry
}

// geScalarMultBase computes h = a*B, where
//   a = a[0]+256*a[1]+...+256^31 a[31]
//   B is the Ed25519 base point (x,4/5) with x positive.
//
// Preconditions:
//   a[31] <= 127
func GeScalarMultBase(h *ExtendedGroupElement, a *[32]byte) {
	var e [64]int8
	computeScalarWindow4(a, &e)

	h.Zero()
	var t PreComputedGroupElement
	var r CompletedGroupElement
	for i := int32(1); i < 64; i += 2 {
		selectPreComputed(&t, i/2, int32(e[i]))
		r.MixedAdd(h, &t)
		r.ToExtended(h)
	}

	var s ProjectiveGroupElement

	h.Double(&r)
	r.ToProjective(&s)
	s.Double(&r)
	r.ToProjective(&s)
	s.Double(&r)
	r.ToProjective(&s)
	s.Double(&r)
	r.ToExtended(h)

	for i := int32(0); i < 64; i += 2 {
		selectPreComputed(&t, i/2, int32(e[i]))
		r.MixedAdd(h, &t)
		r.ToExtended(h)
	}
}

func selectCached(c *CachedGroupElement, Ai *[8]CachedGroupElement, b int32) {
	bNegative := negative(b)
	bAbs := b - (((-bNegative) & b) << 1)

	// in constant-time pick cached multiplier for exponent 0 through 8
	c.Zero()
	for i := int32(0); i < 8; i++ {
		c.CMove(&Ai[i], equal(bAbs, i+1))
	}

	// in constant-time compute negated version, conditionally use it
	var minusC CachedGroupElement
	minusC.Neg(c)
	c.CMove(&minusC, bNegative)
}

// geScalarMult computes h = a*B, where
//   a = a[0]+256*a[1]+...+256^31 a[31]
//   B is the Ed25519 base point (x,4/5) with x positive.
//
// Preconditions:
//   a[31] <= 127
func GeScalarMult(h *ExtendedGroupElement, a *[32]byte, A *ExtendedGroupElement) {
	var t CompletedGroupElement
	var u ExtendedGroupElement
	var r ProjectiveGroupElement
	var c CachedGroupElement
	var i int

	// Break the exponent into 4-bit nybbles.
	var e [64]int8
	computeScalarWindow4(a, &e)

	// compute cached array of multiples of A from 1A through 8A
	var Ai [8]CachedGroupElement // A,1A,2A,3A,4A,5A,6A,7A
	A.ToCached(&Ai[0])
	for i := 0; i < 7; i++ {
		t.Add(A, &Ai[i])
		t.ToExtended(&u)
		u.ToCached(&Ai[i+1])
	}

	// special case for exponent nybble i == 63
	u.Zero()
	selectCached(&c, &Ai, int32(e[63]))
	t.Add(&u, &c)

	for i = 62; i >= 0; i-- {

		// t <<= 4
		t.ToProjective(&r)
		r.Double(&t)
		t.ToProjective(&r)
		r.Double(&t)
		t.ToProjective(&r)
		r.Double(&t)
		t.ToProjective(&r)
		r.Double(&t)

		// Add next nybble
		t.ToExtended(&u)
		selectCached(&c, &Ai, int32(e[i]))
		t.Add(&u, &c)
	}

	t.ToExtended(h)
}

func GeScalarMultVartime(h *ExtendedGroupElement, a *[32]byte, A *ExtendedGroupElement) {

	var aSlide [256]int8
	var Ai [8]CachedGroupElement // A,3A,5A,7A,9A,11A,13A,15A
	var t CompletedGroupElement
	var u, A2 ExtendedGroupElement
	var r ProjectiveGroupElement
	var i int

	// Slide through the scalar exponent clumping sequences of bits,
	// resulting in only zero or odd multipliers between -15 and 15.
	slide(&aSlide, a)

	// Form an array of odd multiples of A from 1A through 15A,
	// in addition-ready cached group element form.
	// We only need odd multiples of A because slide()
	// produces only odd-multiple clumps of bits.
	A.ToCached(&Ai[0])
	A.Double(&t)
	t.ToExtended(&A2)
	for i := 0; i < 7; i++ {
		t.Add(&A2, &Ai[i])
		t.ToExtended(&u)
		u.ToCached(&Ai[i+1])
	}

	// Process the multiplications from most-significant bit downward
	for i = 255; ; i-- {
		if i < 0 { // no bits set
			h.Zero()
			return
		}
		if aSlide[i] != 0 {
			break
		}
	}

	// first (most-significant) nonzero clump of bits
	u.Zero()
	if aSlide[i] > 0 {
		t.Add(&u, &Ai[aSlide[i]/2])
	} else if aSlide[i] < 0 {
		t.Sub(&u, &Ai[(-aSlide[i])/2])
	}
	i--

	// remaining bits
	for ; i >= 0; i-- {
		t.ToProjective(&r)
		r.Double(&t)

		if aSlide[i] > 0 {
			t.ToExtended(&u)
			t.Add(&u, &Ai[aSlide[i]/2])
		} else if aSlide[i] < 0 {
			t.ToExtended(&u)
			t.Sub(&u, &Ai[(-aSlide[i])/2])
		}
	}

	t.ToExtended(h)
}
