// +build amd64

package ed25519

// Field arithmetic in radix 2^51 representation. This code is a port of the
// public domain amd64-51-30k version of ed25519 from SUPERCOP.

// FieldElement represents an element of the field GF(2^255-19). An element t
// represents the integer t[0] + t[1]*2^51 + t[2]*2^102 + t[3]*2^153 +
// t[4]*2^204.
type FieldElement [5]uint64

const maskLow51Bits = (1 << 51) - 1

// carryPropagate brings the limbs below 52, 51, 51, 51, 51 bits. It is split in
// two because of the inliner heuristics. The two functions MUST be called one
// after the other.
func carryPropagate1(v *FieldElement) {
	v[1] += v[0] >> 51
	v[0] &= maskLow51Bits
	v[2] += v[1] >> 51
	v[1] &= maskLow51Bits
	v[3] += v[2] >> 51
	v[2] &= maskLow51Bits
}

func carryPropagate2(v *FieldElement) {
	v[4] += v[3] >> 51
	v[3] &= maskLow51Bits
	v[0] += (v[4] >> 51) * 19
	v[4] &= maskLow51Bits
}

func FeAdd(out, a, b *FieldElement) {
	out[0] = a[0] + b[0]
	out[1] = a[1] + b[1]
	out[2] = a[2] + b[2]
	out[3] = a[3] + b[3]
	out[4] = a[4] + b[4]
	carryPropagate1(out)
	carryPropagate2(out)
}

// FeSub sets out = a - b
func FeSub(out, a, b *FieldElement) {
	// We first add 2 * p, to guarantee the subtraction won't underflow, and
	// then subtract b (which can be up to 2^255 + 2^13 * 19).
	out[0] = (a[0] + 0xFFFFFFFFFFFDA) - b[0]
	out[1] = (a[1] + 0xFFFFFFFFFFFFE) - b[1]
	out[2] = (a[2] + 0xFFFFFFFFFFFFE) - b[2]
	out[3] = (a[3] + 0xFFFFFFFFFFFFE) - b[3]
	out[4] = (a[4] + 0xFFFFFFFFFFFFE) - b[4]
	carryPropagate1(out)
	carryPropagate2(out)
}

// FeNeg sets out = -a
func FeNeg(out, a *FieldElement) {
	var t FieldElement
	FeZero(&t)
	FeSub(out, &t, a)
}

// FeSquare2 calculates out = 2 * a * a.
func FeSquare2(out, a *FieldElement) {
	FeSquare(out, a)
	FeAdd(out, out, out)
}

// Replace (f,g) with (g,g) if b == 1;
// replace (f,g) with (f,g) if b == 0.
//
// Preconditions: b in {0,1}.
func FeCMove(f, g *FieldElement, b int32) {
	negate := (1<<64 - 1) * uint64(b)
	f[0] ^= negate & (f[0] ^ g[0])
	f[1] ^= negate & (f[1] ^ g[1])
	f[2] ^= negate & (f[2] ^ g[2])
	f[3] ^= negate & (f[3] ^ g[3])
	f[4] ^= negate & (f[4] ^ g[4])
}

func FeFromBytes(v *FieldElement, buf []byte) {
	if len(buf) != 32 {
		panic("invalid field element input size")
	}

	v[0] = (uint64(buf[0]) | (uint64(buf[1]) << 8) | (uint64(buf[2]) << 16) |
		(uint64(buf[3]) << 24) | (uint64(buf[4]) << 32) |
		(uint64(buf[5]) << 40) | (uint64(buf[6]&7) << 48))
	v[1] = ((uint64(buf[6]) >> 3) | (uint64(buf[7]) << 5) |
		(uint64(buf[8]) << 13) | (uint64(buf[9]) << 21) |
		(uint64(buf[10]) << 29) | (uint64(buf[11]) << 37) |
		(uint64(buf[12]&63) << 45))
	v[2] = ((uint64(buf[12]) >> 6) | (uint64(buf[13]) << 2) |
		(uint64(buf[14]) << 10) | (uint64(buf[15]) << 18) |
		(uint64(buf[16]) << 26) | (uint64(buf[17]) << 34) |
		(uint64(buf[18]) << 42) | (uint64(buf[19]&1) << 50))
	v[3] = ((uint64(buf[19]) >> 1) | (uint64(buf[20]) << 7) |
		(uint64(buf[21]) << 15) | (uint64(buf[22]) << 23) |
		(uint64(buf[23]) << 31) | (uint64(buf[24]) << 39) |
		(uint64(buf[25]&15) << 47))
	v[4] = ((uint64(buf[25]) >> 4) | (uint64(buf[26]) << 4) |
		(uint64(buf[27]) << 12) | (uint64(buf[28]) << 20) |
		(uint64(buf[29]) << 28) | (uint64(buf[30]) << 36) |
		(uint64(buf[31]&127) << 44))
}

func FeToBytes(r *[32]byte, v *FieldElement) {
	var t FieldElement
	FeReduce(&t, v)

	r[0] = byte(t[0] & 0xff)
	r[1] = byte((t[0] >> 8) & 0xff)
	r[2] = byte((t[0] >> 16) & 0xff)
	r[3] = byte((t[0] >> 24) & 0xff)
	r[4] = byte((t[0] >> 32) & 0xff)
	r[5] = byte((t[0] >> 40) & 0xff)
	r[6] = byte((t[0] >> 48))

	r[6] ^= byte((t[1] << 3) & 0xf8)
	r[7] = byte((t[1] >> 5) & 0xff)
	r[8] = byte((t[1] >> 13) & 0xff)
	r[9] = byte((t[1] >> 21) & 0xff)
	r[10] = byte((t[1] >> 29) & 0xff)
	r[11] = byte((t[1] >> 37) & 0xff)
	r[12] = byte((t[1] >> 45))

	r[12] ^= byte((t[2] << 6) & 0xc0)
	r[13] = byte((t[2] >> 2) & 0xff)
	r[14] = byte((t[2] >> 10) & 0xff)
	r[15] = byte((t[2] >> 18) & 0xff)
	r[16] = byte((t[2] >> 26) & 0xff)
	r[17] = byte((t[2] >> 34) & 0xff)
	r[18] = byte((t[2] >> 42) & 0xff)
	r[19] = byte((t[2] >> 50))

	r[19] ^= byte((t[3] << 1) & 0xfe)
	r[20] = byte((t[3] >> 7) & 0xff)
	r[21] = byte((t[3] >> 15) & 0xff)
	r[22] = byte((t[3] >> 23) & 0xff)
	r[23] = byte((t[3] >> 31) & 0xff)
	r[24] = byte((t[3] >> 39) & 0xff)
	r[25] = byte((t[3] >> 47))

	r[25] ^= byte((t[4] << 4) & 0xf0)
	r[26] = byte((t[4] >> 4) & 0xff)
	r[27] = byte((t[4] >> 12) & 0xff)
	r[28] = byte((t[4] >> 20) & 0xff)
	r[29] = byte((t[4] >> 28) & 0xff)
	r[30] = byte((t[4] >> 36) & 0xff)
	r[31] = byte((t[4] >> 44))
}

func FeReduce(t, v *FieldElement) {
	// Copy v
	*t = *v
	carryPropagate1(t)
	carryPropagate2(t)
	// We now have a field element t < 2^255, but need t <= 2^255-19

	// Get the carry bit
	c := (t[0] + 19) >> 51
	c = (t[1] + c) >> 51
	c = (t[2] + c) >> 51
	c = (t[3] + c) >> 51
	c = (t[4] + c) >> 51

	t[0] += 19 * c

	t[1] += t[0] >> 51
	t[0] = t[0] & maskLow51Bits
	t[2] += t[1] >> 51
	t[1] = t[1] & maskLow51Bits
	t[3] += t[2] >> 51
	t[2] = t[2] & maskLow51Bits
	t[4] += t[3] >> 51
	t[3] = t[3] & maskLow51Bits
	// no additional carry
	t[4] = t[4] & maskLow51Bits
}
