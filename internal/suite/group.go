package suite

import (
	"hash"
	"math/big"
)

// memory-hard function, you can feed either an Scrypt or Argon2i/d (RFC uses scrypt but you may not want to.)
type MHF func(password, salt []byte, len int) ([]byte, error)

type CipherSuiteID int

type CipherSuite interface {
	Hash() hash.Hash
	Group() Group
	Mhf([]byte, []byte) ([]byte, error)
	HashDigest([]byte) []byte
	HashSize() int
	DeriveKey([]byte, []byte, []byte) []byte
	Mac([]byte, []byte) []byte
	MacEqual([]byte, []byte) bool
}

type Group interface {
	M() Element
	N() Element
	RandomElement() (Element, error)
	RandomScalar() (Scalar, error)
	CofactorScalar() Scalar
	ClearCofactor(Element) Element
	Order() *big.Int
	String() string   // name of the group
	ScalarLen() int   // Max length of scalars in bytes
	Scalar() Scalar   // Create new scalar
	ElementLen() int  // Max length of element in bytes
	Element() Element // Create new element
}

type Scalar interface {
	FromBytes([]byte) error
	Bytes() []byte
	Negate(a Scalar) Scalar
}

type Element interface {
	FromBytes([]byte) error
	Bytes() []byte
	Equal(s2 Element) bool
	Identity() Element
	Add(a, b Element) Element
	Negate(a Element) Element
	ScalarMult(s Scalar, p Element) Element
}
