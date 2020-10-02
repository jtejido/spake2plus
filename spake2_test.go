package spake2plus

import (
	"github.com/jtejido/spake2plus/internal/suite"
	"github.com/stretchr/testify/assert"
	"testing"
)

var mhfScrypt = Scrypt(16, 1, 1)

type Suite func(mhf suite.MHF) suite.CipherSuite

var testSuites = []Suite{
	P256Sha256HkdfHmac,
	P384Sha256HkdfHmac,
	P256Sha512HkdfHmac,
	P384Sha512HkdfHmac,
	P521Sha512HkdfHmac,
	Ed25519Sha256HkdfHmac,
	Ed448Sha512HkdfHmac,
}

func testSPAKE2PlusScrypt(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	db := NewMapLookup()
	suite := testSuite(mhf)
	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")

	server, err := NewServer(suite, db, serverIdentity)
	if !assert.NoError(t, err) {
		return
	}

	client, err := NewClient(suite, clientIdentity, serverIdentity, password, salt)
	if !assert.NoError(t, err) {
		return
	}

	// original v
	v, err := client.Verifier()

	// register identity with its Verifier to the server.
	db.Add(clientIdentity, v)

	messageA, err := client.EphemeralPublic()
	if !assert.NoError(t, err) {
		return
	}

	smat, sharedSecretB, err := server.Handshake(clientIdentity, messageA)
	if !assert.NoError(t, err) {
		return
	}

	sharedSecretA, err := client.CompleteHandshake(smat)
	if !assert.NoError(t, err) {
		return
	}

	// B sends its confirmation first. Send this to A
	confirmationB := sharedSecretB.Confirmation()

	// A got pB along with confirmation from B, pass its own cA to B
	// A checks first
	err = sharedSecretA.Verify(confirmationB)
	if !assert.NoError(t, err) {
		return
	}

	// A will send confirmation to B if cB checks out
	confirmationA := sharedSecretA.Confirmation()

	// server would fetch the earlier generated shared secret with A from DB
	err = sharedSecretB.Verify(confirmationA)
	if !assert.NoError(t, err) {
		return
	}

	// A and B have a common shared secret.
	assert.Equal(t, sharedSecretA.Bytes(), sharedSecretB.Bytes())
}

func testSPAKE2PlusWithWrongPassword(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	db := NewMapLookup()
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")

	server, err := NewServer(suite, db, serverIdentity)
	if !assert.NoError(t, err) {
		return
	}

	client, err := NewClient(suite, clientIdentity, serverIdentity, password, salt)
	if !assert.NoError(t, err) {
		return
	}

	// original v
	v, err := client.Verifier()

	// register real identity with its Verifier to the server.
	db.Add(clientIdentity, v)

	// Creates a SPAKE2 client ("adversary") and a SPAKE2 server.
	enemy, err := NewClient(suite, clientIdentity, serverIdentity, []byte("a_wrong_password"), salt)
	if !assert.NoError(t, err) {
		return
	}

	messageA, err := enemy.EphemeralPublic()
	if !assert.NoError(t, err) {
		return
	}

	smat, sharedSecretB, err := server.Handshake(clientIdentity, messageA)
	if !assert.NoError(t, err) {
		return
	}

	sharedSecretEnemy, err := enemy.CompleteHandshake(smat)
	if !assert.NoError(t, err) {
		return
	}

	// B sends its confirmation first. Send this to A
	confirmationB := sharedSecretB.Confirmation()

	// A got pB along with confirmation from B, pass its own cA to B
	// A checks first and fails
	err = sharedSecretEnemy.Verify(confirmationB)
	assert.Error(t, err)
	// At this point, you should show an incorrect password error to user.

	// But, an attacker will still attempt to send wrong confirmation to B just to see if it will go through
	confirmationA := sharedSecretEnemy.Confirmation()

	// server would fetch the earlier generated shared secret with A from DB
	// B verifies the confirmation message from A - and fails.
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func testSPAKE2PlusWithWrongClientIdentity(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	db := NewMapLookup()
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")

	server, err := NewServer(suite, db, serverIdentity)
	if !assert.NoError(t, err) {
		return
	}

	client, err := NewClient(suite, clientIdentity, serverIdentity, password, salt)
	if !assert.NoError(t, err) {
		return
	}

	// original v
	v, err := client.Verifier()

	// register identity with its Verifier to the server.
	db.Add(clientIdentity, v)

	// Creates a SPAKE2 client ("adversary") and a SPAKE2 server.
	enemy, err := NewClient(suite, []byte("another_client"), serverIdentity, []byte("another_password"), salt)
	if !assert.NoError(t, err) {
		return
	}

	messageA, err := enemy.EphemeralPublic()
	if !assert.NoError(t, err) {
		return
	}

	// the fake identity would be checked against the server's db
	// To avoid user enumeration, we should proceed with dummy verifier pair
	smat, sharedSecretB, err := server.Handshake([]byte("another_client"), messageA)
	if !assert.NoError(t, err) {
		return
	}

	// A got pB along with confirmation from B, pass its own cA to B
	sharedSecretEnemy, err := enemy.CompleteHandshake(smat)
	if !assert.NoError(t, err) {
		return
	}

	// An attacker will still attempt to send wrong confirmation to B just to see if it will go through
	confirmationA := sharedSecretEnemy.Confirmation()
	err = sharedSecretB.Verify(confirmationA)
	assert.Error(t, err)
}

func testSPAKE2PlusWithWrongServerIdentity(t *testing.T, testSuite Suite, mhf suite.MHF) {
	// Defines the cipher suite
	db := NewMapLookup()
	suite := testSuite(mhf)

	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")

	// Creates a SPAKE2 instance
	server, err := NewServer(suite, db, []byte("another_server"))
	if !assert.NoError(t, err) {
		return
	}

	client, err := NewClient(suite, clientIdentity, serverIdentity, password, salt)
	if !assert.NoError(t, err) {
		return
	}

	// original v
	v, err := client.Verifier()

	// register identity with its Verifier to the server.
	db.Add(clientIdentity, v)

	messageA, err := client.EphemeralPublic()
	if !assert.NoError(t, err) {
		return
	}

	// the fake identity would be checked against the server's db
	smat, sharedSecretB, err := server.Handshake(clientIdentity, messageA)
	if !assert.NoError(t, err) {
		return
	}

	sharedSecretA, err := client.CompleteHandshake(smat)
	if !assert.NoError(t, err) {
		return
	}

	// A verifies the confirmation message from B - and fails.
	confirmationB := sharedSecretB.Confirmation()
	err = sharedSecretA.Verify(confirmationB)
	assert.Error(t, err)
}

func TestSPAKE2PlusScrypt(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2PlusScrypt(t, s, mhfScrypt)
	}
}

func TestSPAKE2PlusWithWrongPassword(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2PlusWithWrongPassword(t, s, mhfScrypt)
	}
}

func TestSPAKE2PlusWithWrongClientIdentity(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2PlusWithWrongClientIdentity(t, s, mhfScrypt)
	}
}

func TestSPAKE2PlusWithWrongServerIdentity(t *testing.T) {
	for _, s := range testSuites {
		testSPAKE2PlusWithWrongServerIdentity(t, s, mhfScrypt)
	}
}

func benchSPAKE2PlusScrypt(b *testing.B, testSuite Suite, mhf suite.MHF) {
	db := NewMapLookup()
	suite := testSuite(mhf)
	clientIdentity := []byte("client")
	serverIdentity := []byte("server")
	password := []byte("password")
	salt := []byte("NaCl")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// single round without preamble
		server, _ := NewServer(suite, db, serverIdentity)
		client, _ := NewClient(suite, clientIdentity, serverIdentity, password, salt)

		v, _ := client.Verifier()

		db.Add(clientIdentity, v)

		messageA, _ := client.EphemeralPublic()

		smat, sharedSecretB, _ := server.Handshake(clientIdentity, messageA)

		sharedSecretA, _ := client.CompleteHandshake(smat)

		confirmationA := sharedSecretA.Confirmation()
		confirmationB := sharedSecretB.Confirmation()

		sharedSecretA.Verify(confirmationB)
		sharedSecretB.Verify(confirmationA)
	}
}

func BenchmarkSPAKE2PlusEd25519Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, Ed25519Sha256HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2PlusEd448Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, Ed448Sha512HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2PlusP256Sha256Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, P256Sha256HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2PlusP384Sha256Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, P384Sha256HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2PlusP256Sha512Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, P256Sha512HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2PlusP384Sha512Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, P384Sha512HkdfHmac, mhfScrypt)
}
func BenchmarkSPAKE2PlusP521Sha512Scrypt(b *testing.B) {
	benchSPAKE2PlusScrypt(b, P521Sha512HkdfHmac, mhfScrypt)
}
