// +build amd64
// +build go1.13

package ed25519

import "math/bits"

func madd64(lo, hi, a, b uint64) (ol uint64, oh uint64) {
	oh, ol = bits.Mul64(a, b)
	var c uint64
	ol, c = bits.Add64(ol, lo, 0)
	oh, _ = bits.Add64(oh, hi, c)
	return
}

func mul51(a uint64, b uint32) (lo uint64, hi uint64) {
	mh, ml := bits.Mul64(a, uint64(b))
	lo = ml & maskLow51Bits
	hi = (mh << 13) | (ml >> 51)
	return
}
