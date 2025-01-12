package ssh

import (
    "golang.org/x/crypto/chacha20poly1305"
)

// Chacha20poly1305 Encrypt/Decrypt
type CipherChacha20poly1305 struct {
    keySize    int
    nonceSize  int
    identifier string
}

// KeySize
func (this CipherChacha20poly1305) KeySize() int {
    return this.keySize
}

// BlockSize
func (this CipherChacha20poly1305) BlockSize() int {
    return this.nonceSize
}

// oid name
func (this CipherChacha20poly1305) Name() string {
    return this.identifier
}

// Encrypt
func (this CipherChacha20poly1305) Encrypt(key, plaintext []byte) ([]byte, error) {
    nonce := key[this.keySize : this.keySize+this.nonceSize]

    aead, err := chacha20poly1305.New(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    return ciphertext, nil
}

// Decrypt
func (this CipherChacha20poly1305) Decrypt(key, ciphertext []byte) ([]byte, error) {
    nonce := key[this.keySize : this.keySize+this.nonceSize]

    aead, err := chacha20poly1305.New(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}
