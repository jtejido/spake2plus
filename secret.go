package spake2plus

import (
	"errors"
	"github.com/jtejido/spake2plus/internal/suite"
)

type SharedSecret struct {
	suite                                  suite.CipherSuite
	msg, remoteMsg                         []byte
	sharedSecret                           []byte
	keySecret                              []byte
	keyConfirmation, remoteKeyConfirmation []byte
	confirmation, remoteConfirmation       []byte
}

func newSharedSecret(sharedSecret, keySecret, msg, remoteMsg, keyConfirmation, remoteKeyConfirmation []byte, s suite.CipherSuite) *SharedSecret {
	return &SharedSecret{s, msg, remoteMsg, sharedSecret, keySecret, keyConfirmation, remoteKeyConfirmation, nil, nil}
}

func (s *SharedSecret) generateConfirmations() {
	s.confirmation = s.suite.Mac(s.remoteMsg, s.keyConfirmation)
	s.remoteConfirmation = s.suite.Mac(s.msg, s.remoteKeyConfirmation)
}

// send this to server once verification is complete
func (s *SharedSecret) Confirmation() []byte {
	if s.confirmation == nil {
		s.generateConfirmations()
	}

	return s.confirmation
}

// Verify verifies an incoming confirmation message.
func (s *SharedSecret) Verify(incomingConfirmation []byte) error {
	if s.remoteConfirmation == nil {
		s.generateConfirmations()
	}
	if !s.suite.MacEqual(incomingConfirmation, s.remoteConfirmation) {
		return errors.New("Verification Failed")
	}
	return nil
}

func (s SharedSecret) Bytes() []byte {
	return s.sharedSecret
}
