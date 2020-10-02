// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

// This file contains field element logic that is independent of the
// representation.

var zero FieldElement

func load3(in []byte) int64 {
	var r int64
	r = int64(in[0])
	r |= int64(in[1]) << 8
	r |= int64(in[2]) << 16
	return r
}

func load4(in []byte) int64 {
	var r int64
	r = int64(in[0])
	r |= int64(in[1]) << 8
	r |= int64(in[2]) << 16
	r |= int64(in[3]) << 24
	return r
}

func FeZero(fe *FieldElement) {
	copy(fe[:], zero[:])
}

func FeOne(fe *FieldElement) {
	FeZero(fe)
	fe[0] = 1
}

func FeCopy(dst, src *FieldElement) {
	copy(dst[:], src[:])
}

func FeIsNegative(f *FieldElement) byte {
	var s [32]byte
	FeToBytes(&s, f)
	return s[0] & 1
}

func FeIsNonZero(f *FieldElement) int32 {
	var s [32]byte
	FeToBytes(&s, f)
	var x uint8
	for _, b := range s {
		x |= b
	}
	x |= x >> 4
	x |= x >> 2
	x |= x >> 1
	return int32(x & 1)
}

func FeInvert(out, z *FieldElement) {
	var t0, t1, t2, t3 FieldElement
	var i int

	FeSquare(&t0, z)        // 2^1
	FeSquare(&t1, &t0)      // 2^2
	for i = 1; i < 2; i++ { // 2^3
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, z, &t1)      // 2^3 + 2^0
	FeMul(&t0, &t0, &t1)    // 2^3 + 2^1 + 2^0
	FeSquare(&t2, &t0)      // 2^4 + 2^2 + 2^1
	FeMul(&t1, &t1, &t2)    // 2^4 + 2^3 + 2^2 + 2^1 + 2^0
	FeSquare(&t2, &t1)      // 5,4,3,2,1
	for i = 1; i < 5; i++ { // 9,8,7,6,5
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)     // 9,8,7,6,5,4,3,2,1,0
	FeSquare(&t2, &t1)       // 10..1
	for i = 1; i < 10; i++ { // 19..10
		FeSquare(&t2, &t2)
	}
	FeMul(&t2, &t2, &t1)     // 19..0
	FeSquare(&t3, &t2)       // 20..1
	for i = 1; i < 20; i++ { // 39..20
		FeSquare(&t3, &t3)
	}
	FeMul(&t2, &t3, &t2)     // 39..0
	FeSquare(&t2, &t2)       // 40..1
	for i = 1; i < 10; i++ { // 49..10
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)     // 49..0
	FeSquare(&t2, &t1)       // 50..1
	for i = 1; i < 50; i++ { // 99..50
		FeSquare(&t2, &t2)
	}
	FeMul(&t2, &t2, &t1)      // 99..0
	FeSquare(&t3, &t2)        // 100..1
	for i = 1; i < 100; i++ { // 199..100
		FeSquare(&t3, &t3)
	}
	FeMul(&t2, &t3, &t2)     // 199..0
	FeSquare(&t2, &t2)       // 200..1
	for i = 1; i < 50; i++ { // 249..50
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)    // 249..0
	FeSquare(&t1, &t1)      // 250..1
	for i = 1; i < 5; i++ { // 254..5
		FeSquare(&t1, &t1)
	}
	FeMul(out, &t1, &t0) // 254..5,3,1,0
}

// Returns whether fe equals a.
func (fe *FieldElement) Equals(a *FieldElement) bool {
	var b FieldElement
	FeSub(&b, fe, a)
	return b.IsNonZeroI() == 0
}

// Returns 1 if fe is non-zero, otherwise 0.
func (fe *FieldElement) IsNonZeroI() int32 {
	var buf [32]byte
	FeToBytes(&buf, fe)
	ret := (binary.LittleEndian.Uint64(buf[0:8]) |
		binary.LittleEndian.Uint64(buf[8:16]) |
		binary.LittleEndian.Uint64(buf[16:24]) |
		binary.LittleEndian.Uint64(buf[24:32]))
	ret |= ret >> 32
	ret |= ret >> 16
	ret |= ret >> 8
	ret |= ret >> 4
	ret |= ret >> 2
	ret |= ret >> 1
	return int32(ret & 1)
}

// Returns 1 if fe is equal to one, otherwise 0.
func (fe *FieldElement) IsOneI() int32 {
	var b, fe1 FieldElement
	FeOne(&fe1)
	FeSub(&b, fe, &fe1)
	return 1 - b.IsNonZeroI()
}

// Returns 1 if fe is negative, otherwise 0.
func (fe *FieldElement) IsNegativeI() int32 {
	var buf [32]byte
	FeToBytes(&buf, fe)
	return int32(buf[0] & 1)
}

// Sets fe to 1/sqrt(a).  Requires a to be a square.  Returns fe.
func FeInvSqrt(out, a *FieldElement) {
	var den2, den3, den4, den6, chk, t, t2 FieldElement
	FeSquare(&den2, a)
	FeMul(&den3, &den2, a)
	FeSquare(&den4, &den2)
	FeMul(&den6, &den2, &den4)
	FeMul(&t, &den6, a)
	fePow22523(&t, &t)
	FeMul(&t, &t, &den3)
	FeMul(&t2, &t, &sqrtM1)

	FeSquare(&chk, &t)
	FeMul(&chk, &chk, a)

	FeCopy(out, &t)
	FeCMove(out, &t2, 1-chk.IsOneI())
}

// Sets fe to sqrt(a).  Requires a to be a square.  Returns fe.
func FeSqrt(out, a *FieldElement) {
	var aCopy FieldElement
	FeCopy(&aCopy, a)
	FeInvSqrt(out, a)
	FeMul(out, out, &aCopy)

	var fn FieldElement
	FeNeg(&fn, out)
	FeCMove(out, &fn, out.IsNegativeI())
}

func fePow22523(out, z *FieldElement) {
	var t0, t1, t2 FieldElement
	var i int

	FeSquare(&t0, z)
	for i = 1; i < 1; i++ {
		FeSquare(&t0, &t0)
	}
	FeSquare(&t1, &t0)
	for i = 1; i < 2; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, z, &t1)
	FeMul(&t0, &t0, &t1)
	FeSquare(&t0, &t0)
	for i = 1; i < 1; i++ {
		FeSquare(&t0, &t0)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t1, &t0)
	for i = 1; i < 5; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t1, &t0)
	for i = 1; i < 10; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, &t1, &t0)
	FeSquare(&t2, &t1)
	for i = 1; i < 20; i++ {
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)
	FeSquare(&t1, &t1)
	for i = 1; i < 10; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t1, &t0)
	for i = 1; i < 50; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, &t1, &t0)
	FeSquare(&t2, &t1)
	for i = 1; i < 100; i++ {
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)
	FeSquare(&t1, &t1)
	for i = 1; i < 50; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t0, &t0)
	for i = 1; i < 2; i++ {
		FeSquare(&t0, &t0)
	}
	FeMul(out, &t0, z)
}

func (fe *FieldElement) String() string {
	s := "FieldElement{"
	for i := range fe {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%d", fe[i])
	}
	s += "}"
	return s
}

//
// TESTING PURPOSES ONLY!!
//
func (fe *FieldElement) bigInt() *big.Int {
	var ret big.Int
	var buf, rBuf [32]byte
	FeToBytes(&buf, fe)
	for i := 0; i < 32; i++ {
		rBuf[i] = buf[31-i]
	}

	return ret.SetBytes(rBuf[:])
}

func (fe *FieldElement) setBigInt(x *big.Int) {
	var v, bi25519 big.Int
	bi25519.SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	buf := v.Mod(x, &bi25519).Bytes()
	var rBuf [32]byte
	for i := 0; i < len(buf) && i < 32; i++ {
		rBuf[i] = buf[len(buf)-i-1]
	}

	FeFromBytes(fe, rBuf[:])
}
