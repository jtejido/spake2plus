package spake2plus

import (
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
)

type Server struct {
	db             Lookup
	suite          suite.CipherSuite
	y              suite.Scalar
	serverIdentity []byte
}

func NewServer(s suite.CipherSuite, lookup Lookup, serverIdentity []byte) (*Server, error) {
	y, err := s.Group().RandomScalar()
	if err != nil {
		return nil, err
	}
	return newServer(s, lookup, serverIdentity, y)
}

func newServer(s suite.CipherSuite, lookup Lookup, serverIdentity []byte, y suite.Scalar) (*Server, error) {
	return &Server{lookup, s, y, serverIdentity}, nil
}

func (s *Server) Handshake(identity, A []byte) (*ServerMaterial, *SharedSecret, error) {
	// Load the verifier from DB
	info, ok := s.db.Fetch(identity)
	incomingElement := s.suite.Group().Element()
	err := incomingElement.FromBytes(A)
	if err != nil {
		return nil, nil, err
	}

	if isElementSmall(s.suite, incomingElement) {
		return nil, nil, errors.New("Corrupt Message")
	}

	if !ok {
		// simulate computations to avoid user enumeration
		sc, _ := s.suite.Group().RandomScalar()
		elem, _ := s.suite.Group().RandomElement()
		info = &UserInfo{
			Verifier: &Verifier{
				Verifier: VerifierPair{
					V1: sc.Bytes(),
					V2: elem.Bytes(),
				},
			},
		}
	}

	v1 := info.Verifier.Verifier.V1
	v2 := info.Verifier.Verifier.V2
	w0 := s.suite.Group().Scalar()
	err = w0.FromBytes(padScalarBytes(v1, s.suite.Group().ScalarLen()))
	if err != nil {
		return nil, nil, err
	}

	// Y=y*P+w0*N
	Y := s.suite.Group().Element().ScalarMult(s.y, nil)
	Y.Add(Y, s.suite.Group().Element().ScalarMult(w0, s.suite.Group().N()))
	YBytes := Y.Bytes()

	LElement := s.suite.Group().Element()
	err = LElement.FromBytes(v2)
	if err != nil {
		return nil, nil, err
	}

	// B computes Z as h*y*(X-w0*M) and V as h*y*L.
	tmp := s.suite.Group().Element().ScalarMult(s.suite.Group().Scalar().Negate(w0), s.suite.Group().M())
	tmp.Add(incomingElement, tmp)

	ZElement := s.suite.Group().Element().ScalarMult(s.y, tmp)
	ZElement = s.suite.Group().ClearCofactor(ZElement)
	ZBytes := ZElement.Bytes()

	VElement := s.suite.Group().Element().ScalarMult(s.y, LElement)
	VElement = s.suite.Group().ClearCofactor(VElement)
	VBytes := VElement.Bytes()

	// You better store it elsewhere, regardless if valid user or not, as you'll be checking multiple users, that's why I'm returning it.
	sharedSecret := newServerSharedSecret(identity, s.serverIdentity, A, YBytes, ZBytes, VBytes, v1, s.suite)

	return &ServerMaterial{
		B: YBytes,
	}, sharedSecret, nil
}

func newServerSharedSecret(idA, idB, X, Y, Z, V, w0 []byte, s suite.CipherSuite) *SharedSecret {
	Ke, Ka, kcA, kcB := generateSharedSecrets(s, idA, idB, X, Y, Z, V, w0)
	return newSharedSecret(Ke, Ka, Y, X, kcB, kcA, s)
}
