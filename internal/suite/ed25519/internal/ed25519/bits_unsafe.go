// +build amd64
// +build !go1.13

package ed25519

import "unsafe"

func madd64(lo, hi, a, b uint64) (ol uint64, oh uint64) {
	t1 := (a>>32)*(b&0xFFFFFFFF) + ((a & 0xFFFFFFFF) * (b & 0xFFFFFFFF) >> 32)
	t2 := (a&0xFFFFFFFF)*(b>>32) + (t1 & 0xFFFFFFFF)
	ol = (a * b) + lo
	cmp := ol < lo
	oh = hi + (a>>32)*(b>>32) + t1>>32 + t2>>32 + uint64(*(*byte)(unsafe.Pointer(&cmp)))
	return
}

const mask32 = 1<<32 - 1

func mul51(a uint64, b uint32) (lo uint64, hi uint64) {
	w0 := (a & mask32) * uint64(b)
	t := (a>>32)*uint64(b) + w0>>32
	w1 := t & mask32
	w2 := t >> 32
	mh := w2 + w1>>32
	ml := a * uint64(b)

	lo = ml & maskLow51Bits
	hi = (mh << 13) | (ml >> 51)
	return
}
