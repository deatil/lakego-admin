package ssh

import (
    "crypto/cipher"
)

// gcm mode
type CipherGCM struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    nonceSize  int
    identifier string
}

// KeySize
func (this CipherGCM) KeySize() int {
    return this.keySize
}

// BlockSize
func (this CipherGCM) BlockSize() int {
    return this.nonceSize
}

// oid name
func (this CipherGCM) Name() string {
    return this.identifier
}

// Encrypt
func (this CipherGCM) Encrypt(key, plaintext []byte) ([]byte, error) {
    nonce := key[this.keySize : this.keySize+this.nonceSize]

    block, err := this.cipherFunc(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, this.nonceSize)
    if err != nil {
        return nil, err
    }

    // Encrypt data
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    return ciphertext, nil
}

// Decrypt
func (this CipherGCM) Decrypt(key, ciphertext []byte) ([]byte, error) {
    nonce := key[this.keySize : this.keySize+this.nonceSize]

    block, err := this.cipherFunc(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}
