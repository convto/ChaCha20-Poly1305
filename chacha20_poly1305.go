// ChaCha20-Poly1305 implementation for learning purposes. Do not use in production.
// This package does not implement cipher.AEAD interface
// to keep inputs/outputs explicit for learning purposes.
package chacha20_poly1305

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	chacha20 "github.com/convto/ChaCha20"
	poly1305 "github.com/convto/Poly1305"
)

func Seal(sessionKey [32]byte, nonce [12]byte, plaintext, additionalData []byte) (chipertext []byte, tag []byte) {
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}

	// Generate the Poly1305 key
	stream := chacha20.NewCipher(sessionKey, 0, nonce)
	var polyKey [32]byte
	stream.XORKeyStream(polyKey[:], polyKey[:])

	// Encrypt the plaintext
	stream.SetCounter(1)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Generate the Poly1305 authentication tag
	r := [16]byte(polyKey[:16])
	s := [16]byte(polyKey[16:32])
	mac := poly1305.New(r, s)
	var buf bytes.Buffer
	buf.Write(withPadding(additionalData))
	buf.Write(withPadding(ciphertext))
	binary.Write(&buf, binary.LittleEndian, uint64(len(additionalData)))
	binary.Write(&buf, binary.LittleEndian, uint64(len(ciphertext)))

	return ciphertext, mac.Sum(buf.Bytes())
}

func Open(sessionKey [32]byte, nonce [12]byte, ciphertext, tag, additionalData []byte) ([]byte, error) {
	// Generate the Poly1305 key
	stream := chacha20.NewCipher(sessionKey, 0, nonce)
	var polyKey [32]byte
	stream.XORKeyStream(polyKey[:], polyKey[:])

	// Decrypt the ciphertext
	stream.SetCounter(1)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	// Generate the Poly1305 authentication tag
	r := [16]byte(polyKey[:16])
	s := [16]byte(polyKey[16:32])
	mac := poly1305.New(r, s)
	var buf bytes.Buffer
	buf.Write(withPadding(additionalData))
	buf.Write(withPadding(ciphertext))
	binary.Write(&buf, binary.LittleEndian, uint64(len(additionalData)))
	binary.Write(&buf, binary.LittleEndian, uint64(len(ciphertext)))
	t := mac.Sum(buf.Bytes())

	// Verify the authentication tag
	if !slices.Equal(t, tag) {
		return nil, errors.New("invalid tag")
	}
	return []byte(plaintext), nil
}

func withPadding(b []byte) []byte {
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		return append(b, buf[:padLen]...)
	}
	return b
}
