package ed25519

import (
	"bytes"
	"math/big"
	"math/rand"
	"os"
	"testing"
)

var bi25519 big.Int
var biL big.Int
var rnd *rand.Rand

func TestFeMul(t *testing.T) {
	var bi1, bi2, bi3 big.Int
	var fe1, fe2, fe3 FieldElement
	for i := 0; i < 100; i++ {
		bi1.Rand(rnd, &bi25519)
		bi2.Rand(rnd, &bi25519)
		bi3.Mul(&bi1, &bi2)
		bi3.Mod(&bi3, &bi25519)
		fe1.setBigInt(&bi1)
		fe2.setBigInt(&bi2)
		FeMul(&fe3, &fe1, &fe2)
		if fe3.bigInt().Cmp(&bi3) != 0 {
			t.Fatalf("%v * %v = %v != %v", &bi1, &bi2, &bi3, &fe3)
		}
	}
}

func TestFeSquare(t *testing.T) {
	var bi1, bi2 big.Int
	var fe1, fe2 FieldElement
	for i := 0; i < 100; i++ {
		bi1.Rand(rnd, &bi25519)
		bi2.Mul(&bi1, &bi1)
		bi2.Mod(&bi2, &bi25519)
		fe1.setBigInt(&bi1)
		FeSquare(&fe2, &fe1)
		if fe2.bigInt().Cmp(&bi2) != 0 {
			t.Fatalf("%v^2 = %v != %v", &bi1, &bi2, &fe2)
		}
	}
}

func TestFeSub(t *testing.T) {
	var bi1, bi2, bi3 big.Int
	var fe1, fe2, fe3 FieldElement
	for i := 0; i < 100; i++ {
		bi1.Rand(rnd, &bi25519)
		bi2.Rand(rnd, &bi25519)
		bi3.Sub(&bi1, &bi2)

		bi3.Mod(&bi3, &bi25519)
		fe1.setBigInt(&bi1)
		fe2.setBigInt(&bi2)

		FeSub(&fe3, &fe1, &fe2)
		if fe3.bigInt().Cmp(&bi3) != 0 {
			t.Fatalf("%v - %v = %v != %v", &bi1, &bi2, &bi3, &fe3)
		}
	}
}

func TestFeAdd(t *testing.T) {
	var bi1, bi2, bi3 big.Int
	var fe1, fe2, fe3 FieldElement
	for i := 0; i < 100; i++ {
		bi1.Rand(rnd, &bi25519)
		bi2.Rand(rnd, &bi25519)
		bi3.Add(&bi1, &bi2)
		bi3.Mod(&bi3, &bi25519)
		fe1.setBigInt(&bi1)
		fe2.setBigInt(&bi2)

		FeAdd(&fe3, &fe1, &fe2)
		if fe3.bigInt().Cmp(&bi3) != 0 {
			t.Fatalf("%v + %v = %v != %v", &bi1, &bi2, &bi3, &fe3)
		}
	}
}

func TestFeInvert(t *testing.T) {
	var bi1, bi2 big.Int
	var fe1, fe2 FieldElement
	for i := 0; i < 100; i++ {
		bi1.Rand(rnd, &bi25519)
		bi2.ModInverse(&bi1, &bi25519)
		fe1.setBigInt(&bi1)
		FeInvert(&fe2, &fe1)
		if fe2.bigInt().Cmp(&bi2) != 0 {
			t.Fatalf("1/%v = %v != %v", &bi1, &bi2, &fe2)
		}
	}
}

func TestFeSqrt(t *testing.T) {
	var bi big.Int
	var fe1, fe2 FieldElement
	for i := 0; i < 100; i++ {
		bi.Rand(rnd, &bi25519)
		bi.Mul(&bi, &bi)
		bi.Mod(&bi, &bi25519)
		fe1.setBigInt(&bi)
		FeSqrt(&fe2, &fe1)
		if fe2.IsNegativeI() == 1 {
			t.Fatalf("Sqrt(%v) is negative", &bi)
		}
		FeSquare(&fe2, &fe2)
		if !fe1.Equals(&fe2) {
			t.Fatalf("Sqrt(%v) incorrect", &bi)
		}
	}
}

func TestG(t *testing.T) {
	var res1, res2 [32]byte
	g := G()
	g.ToBytes(&res1)
	baseext.ToBytes(&res2)

	if !bytes.Equal(res1[:], res2[:]) {
		t.Errorf("G mismatch")
	}
}

func BenchmarkFeInvert(b *testing.B) {
	var fe FieldElement
	var bi big.Int
	bi.Rand(rnd, &bi25519)
	fe.setBigInt(&bi)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		FeInvert(&fe, &fe)
	}
}

func BenchmarkFeSquare(b *testing.B) {
	var fe FieldElement
	var bi big.Int
	bi.Rand(rnd, &bi25519)
	fe.setBigInt(&bi)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		FeSquare(&fe, &fe)
	}
}

func BenchmarkFeSquare2(b *testing.B) {
	var fe FieldElement
	var bi big.Int
	bi.Rand(rnd, &bi25519)
	fe.setBigInt(&bi)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		FeSquare2(&fe, &fe)
	}
}

func BenchmarkFeMul(b *testing.B) {
	var fe FieldElement
	var bi big.Int
	bi.Rand(rnd, &bi25519)
	fe.setBigInt(&bi)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		FeMul(&fe, &fe, &fe)
	}
}

func TestMain(m *testing.M) {
	bi25519.SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	biL.SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	rnd = rand.New(rand.NewSource(37))
	os.Exit(m.Run())
}
