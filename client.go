package spake2plus

import (
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
)

type Client struct {
	suite          suite.CipherSuite
	x              suite.Scalar
	clientIdentity []byte
	serverIdentity []byte
	verifierW0     []byte
	verifierW1     []byte
	msg            []byte
}

func NewClient(s suite.CipherSuite, clientIdentity, serverIdentity, password, salt []byte) (*Client, error) {
	x, err := s.Group().RandomScalar()

	if err != nil {
		return nil, err
	}

	w0, w1, err := computeW0W1(s, clientIdentity, serverIdentity, password, salt)
	if err != nil {
		return nil, err
	}

	return &Client{s, x, clientIdentity, serverIdentity, w0, w1, nil}, nil
}

// Send this to server during Registration part
func (c *Client) Verifier() (*Verifier, error) {
	w1Scalar := c.suite.Group().Scalar()
	err := w1Scalar.FromBytes(padScalarBytes(c.verifierW1, c.suite.Group().ScalarLen()))
	if err != nil {
		return nil, err
	}

	L := c.suite.Group().Element().ScalarMult(w1Scalar, nil)

	return &Verifier{
		I: c.clientIdentity,
		Verifier: VerifierPair{
			V1: c.verifierW0,
			V2: L.Bytes(),
		},
	}, nil
}

// EphemeralPublic returns A.
// This will be sent to the server.
func (c *Client) EphemeralPublic() ([]byte, error) {
	w0Scalar := c.suite.Group().Scalar()
	err := w0Scalar.FromBytes(padScalarBytes(c.verifierW0, c.suite.Group().ScalarLen()))
	if err != nil {
		return nil, err
	}

	// X=x*P+w0*M
	x := c.suite.Group().Element().ScalarMult(c.x, nil)
	x.Add(x, c.suite.Group().Element().ScalarMult(w0Scalar, c.suite.Group().M()))

	XBytes := x.Bytes()
	c.msg = XBytes

	return XBytes, nil
}

func (c *Client) CompleteHandshake(m *ServerMaterial) (*SharedSecret, error) {
	incomingElement := c.suite.Group().Element()
	err := incomingElement.FromBytes(m.B)
	if err != nil {
		return nil, err
	}

	if isElementSmall(c.suite, incomingElement) {
		return nil, errors.New("Corrupt Message")
	}

	w0Scalar := c.suite.Group().Scalar()
	err = w0Scalar.FromBytes(padScalarBytes(c.verifierW0, c.suite.Group().ScalarLen()))
	if err != nil {
		return nil, err
	}

	w1Scalar := c.suite.Group().Scalar()
	err = w1Scalar.FromBytes(padScalarBytes(c.verifierW1, c.suite.Group().ScalarLen()))
	if err != nil {
		return nil, err
	}

	// A computes Z as h*x*(Y-w0*N), and V as h*w1*(Y-w0*N).
	tmp := c.suite.Group().Element().ScalarMult(c.suite.Group().Scalar().Negate(w0Scalar), c.suite.Group().N())
	tmp.Add(incomingElement, tmp)

	ZElement := c.suite.Group().Element().ScalarMult(c.x, tmp)
	ZElement = c.suite.Group().ClearCofactor(ZElement)
	ZBytes := ZElement.Bytes()

	VElement := c.suite.Group().Element().ScalarMult(w1Scalar, tmp)
	VElement = c.suite.Group().ClearCofactor(VElement)
	VBytes := VElement.Bytes()

	return newClientSharedSecret(c.clientIdentity, c.serverIdentity, c.msg, m.B, ZBytes, VBytes, c.verifierW0, c.suite), nil
}

func newClientSharedSecret(idA, idB, X, Y, Z, V, w0 []byte, s suite.CipherSuite) *SharedSecret {
	Ke, Ka, kcA, kcB := generateSharedSecrets(s, idA, idB, X, Y, Z, V, w0)
	return newSharedSecret(Ke, Ka, X, Y, kcA, kcB, s)
}
