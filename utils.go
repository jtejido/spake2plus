package spake2plus

import (
	"bytes"
	"encoding/binary"
	"github.com/jtejido/spake2plus/internal/suite"
)

func concat(bytesArray ...[]byte) []byte {
	result := []byte{}
	for _, bytes := range bytesArray {
		if len(bytes) > 0 {
			bytesLen := make([]byte, 8)
			binary.LittleEndian.PutUint64(bytesLen, uint64(len(bytes)))
			result = append(result, bytesLen...)
			result = append(result, bytes...)
		}
	}
	return result
}

func padScalarBytes(scBytes []byte, padLen int) []byte {
	if len(scBytes) > padLen {
		return scBytes
	}
	return append(bytes.Repeat([]byte{0}, padLen-len(scBytes)), scBytes...)
}

func appendLenAndContent(b *bytes.Buffer, input []byte) {
	binary.Write(b, binary.LittleEndian, uint64(len(input)))
	b.Write(input)
}

func computeW0W1(s suite.CipherSuite, clientIdentity, serverIdentity, password, salt []byte) ([]byte, []byte, error) {
	wBytes, err := s.Mhf(
		concat(password, clientIdentity, serverIdentity),
		salt,
	)
	if err != nil {
		return nil, nil, err
	}
	hashSize := s.HashSize() / 2
	w0, w1 := wBytes[:hashSize], wBytes[hashSize:]
	return w0, w1, nil
}

func confirmationMACs(ka []byte, s suite.CipherSuite) ([]byte, []byte) {
	info := []byte("ConfirmationKeys")
	Kc := s.DeriveKey(nil, ka, info)
	keyLength := len(Kc)
	return Kc[:keyLength/2], Kc[keyLength/2:]
}

// 4.  Key Schedule and Key Confirmation
//
//    The protocol transcript TT, as defined in Section 3.3, is unique and
//    secret to A and B.  Both parties use TT to derive shared symmetric
//    secrets Ke and Ka as Ke || Ka = Hash(TT).  The length of each key is
//    equal to half of the digest output, e.g., |Ke| = |Ka| = 128 bits for
//    SHA-256.  If the required key size is less than half the digest
//    output, e.g. when using SHA-512 to derive two 128-bit keys, the
//    digest output MAY be truncated.
//
//    Both endpoints use Ka to derive subsequent MAC keys for key
//    confirmation messages.  Specifically, let KcA and KcB be the MAC keys
//    used by A and B, respectively.  A and B compute them as KcA || KcB =
//    KDF(nil, Ka, "ConfirmationKeys")
//
//    The length of each of KcA and KcB is equal to half of the KDF output,
//    e.g., |KcA| = |KcB| = 128 bits for HKDF-SHA256.  If half of the KDF
//    output size exceeds the required key size for the chosen MAC, e.g.
//    when using HKDF-SHA512 as the KDF and CMAC-AES-128 as the MAC, the
//    KDF output MAY be truncated.
//
//    The resulting key schedule for this protocol, given transcript TT, is
//    as follows.
//
//    TT -> Hash(TT) = Ka || Ke
//    Ka -> KDF(nil, Ka, "ConfirmationKeys") = KcA || KcB
//
//    A and B output Ke as the shared secret from the protocol.  Ka and its
//    derived keys (KcA and KcB) are not used for anything except key
//    confirmation.
func generateSharedSecrets(s suite.CipherSuite, idA, idB, X, Y, Z, V, w0 []byte) (Ke, Ka, kcA, kcB []byte) {
	// TT = len(Context) || Context ||     // we dont have this yet, ideally we would have all the required stuff in here, suite ID, h2c ID, etc
	//   || len(A) || A || len(B) || B
	//   || len(M) || M || len(N) || N
	//   || len(X) || X || len(Y) || Y
	//   || len(Z) || Z || len(V) || V
	//   || len(w0) || w0
	transcript := new(bytes.Buffer)
	if len(idA) != 0 {
		appendLenAndContent(transcript, idA)
	}
	if len(idB) != 0 {
		appendLenAndContent(transcript, idB)
	}
	appendLenAndContent(transcript, s.Group().M().Bytes())
	appendLenAndContent(transcript, s.Group().N().Bytes())
	appendLenAndContent(transcript, X)
	appendLenAndContent(transcript, Y)
	appendLenAndContent(transcript, Z)
	appendLenAndContent(transcript, V)
	appendLenAndContent(transcript, w0)

	transcriptBytes := transcript.Bytes()
	transcriptHash := s.HashDigest(transcriptBytes)
	blockSize := len(transcriptHash)

	Ke, Ka = transcriptHash[:blockSize/2], transcriptHash[blockSize/2:]
	kcA, kcB = confirmationMACs(Ka, s)
	return
}

func isElementSmall(s suite.CipherSuite, elem suite.Element) bool {
	return s.Group().ClearCofactor(elem).Equal(s.Group().Element().Identity())
}
