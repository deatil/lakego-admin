package ssh

import (
    "crypto/rc4"
)

// CipherRC4 Encrypt/Decrypt
type CipherRC4 struct {
    keySize    int
    blockSize  int
    identifier string
}

// KeySize
func (this CipherRC4) KeySize() int {
    return this.keySize
}

// BlockSize
func (this CipherRC4) BlockSize() int {
    return this.blockSize
}

// oid name
func (this CipherRC4) Name() string {
    return this.identifier
}

// Encrypt
func (this CipherRC4) Encrypt(key, plaintext []byte) ([]byte, error) {
    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, len(plaintext))
    cipher.XORKeyStream(ciphertext, plaintext)

    return ciphertext, nil
}

// Decrypt
func (this CipherRC4) Decrypt(key, ciphertext []byte) ([]byte, error) {
    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))
    cipher.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// With KeySize
func (this CipherRC4) WithKeySize(keySize int) CipherRC4 {
    this.keySize = keySize

    return this
}
