package chacha20_poly1305

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAEAD_Seal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		key                string
		nonce              string
		plaintext          []byte
		aad                string
		expectedCiphertext string
		expectedTag        string
	}{
		{
			name: "RFC 8439 Section 2.8.2",
			key:  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			// Nonce (12 bytes): fixed-common part (4 bytes) + IV (8 bytes)
			// fixed-common part: 07 00 00 00
			// IV: 40 41 42 43 44 45 46 47
			nonce:              "070000004041424344454647",
			plaintext:          []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
			aad:                "50515253c0c1c2c3c4c5c6c7",
			expectedCiphertext: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
			expectedTag:        "1ae10b594f09e26a7e902ecbd0600691",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, _ := hex.DecodeString(tt.key)
			if len(key) != 32 {
				t.Fatalf("key length is not 32 bytes: %d", len(key))
			}

			nonce, _ := hex.DecodeString(tt.nonce)
			if len(nonce) != 12 {
				t.Fatalf("nonce length is not 12 bytes: %d", len(nonce))
			}

			aad, _ := hex.DecodeString(tt.aad)
			expectedCiphertext, _ := hex.DecodeString(tt.expectedCiphertext)
			expectedTag, _ := hex.DecodeString(tt.expectedTag)

			var sessionKey [32]byte
			copy(sessionKey[:], key)
			aead := &AEAD{sessionKey: sessionKey}

			chipertext, tag := aead.Seal(nonce, tt.plaintext, aad)

			if !bytes.Equal(chipertext, expectedCiphertext) {
				t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", chipertext, expectedCiphertext)
			}

			if !bytes.Equal(tag, expectedTag) {
				t.Errorf("tag mismatch\ngot:  %x\nwant: %x", tag, expectedTag)
			}
		})
	}
}

func TestAEAD_Open(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		key               string
		nonce             string
		ciphertext        string
		tag               string
		aad               string
		expectedPlaintext []byte
		expectedError     bool
		errorDescription  string
	}{
		{
			name: "RFC 8439 Section 2.8.2 - Valid decryption",
			key:  "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			// Nonce (12 bytes): fixed-common part (4 bytes) + IV (8 bytes)
			// fixed-common part: 07 00 00 00
			// IV: 40 41 42 43 44 45 46 47
			nonce:             "070000004041424344454647",
			ciphertext:        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
			tag:               "1ae10b594f09e26a7e902ecbd0600691",
			aad:               "50515253c0c1c2c3c4c5c6c7",
			expectedPlaintext: []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."),
			expectedError:     false,
		},
		{
			name:              "Invalid tag",
			key:               "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			nonce:             "070000004041424344454647",
			ciphertext:        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
			tag:               "0000000000000000000000000000000000", // Invalid tag (all zeros)
			aad:               "50515253c0c1c2c3c4c5c6c7",
			expectedPlaintext: nil,
			expectedError:     true,
		},
		{
			name:              "Tampered ciphertext",
			key:               "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			nonce:             "070000004041424344454647",
			ciphertext:        "ff1a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116", // First byte modified
			tag:               "1ae10b594f09e26a7e902ecbd0600691",
			aad:               "50515253c0c1c2c3c4c5c6c7",
			expectedPlaintext: nil,
			expectedError:     true,
		},
		{
			name:              "Tampered AAD",
			key:               "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			nonce:             "070000004041424344454647",
			ciphertext:        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
			tag:               "1ae10b594f09e26a7e902ecbd0600691",
			aad:               "ff515253c0c1c2c3c4c5c6c7", // First byte modified
			expectedPlaintext: nil,
			expectedError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, _ := hex.DecodeString(tt.key)
			if len(key) != 32 {
				t.Fatalf("key length is not 32 bytes: %d", len(key))
			}

			nonce, _ := hex.DecodeString(tt.nonce)
			if len(nonce) != 12 {
				t.Fatalf("nonce length is not 12 bytes: %d", len(nonce))
			}

			ciphertext, _ := hex.DecodeString(tt.ciphertext)
			tag, _ := hex.DecodeString(tt.tag)
			aad, _ := hex.DecodeString(tt.aad)

			var sessionKey [32]byte
			copy(sessionKey[:], key)
			aead := &AEAD{sessionKey: sessionKey}

			plaintext, err := aead.Open(nonce, ciphertext, tag, aad)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !bytes.Equal(plaintext, tt.expectedPlaintext) {
				t.Errorf("plaintext mismatch\ngot:  %s (%x)\nwant: %s (%x)", plaintext, plaintext, tt.expectedPlaintext, tt.expectedPlaintext)
			}
		})
	}
}
