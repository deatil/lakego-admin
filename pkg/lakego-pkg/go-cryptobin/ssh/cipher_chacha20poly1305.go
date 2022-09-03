package ssh

import (
    "golang.org/x/crypto/chacha20poly1305"
)

// Chacha20poly1305 加密/解密
type CipherChacha20poly1305 struct {
    keySize    int
    nonceSize  int
    identifier string
}

// 值大小
func (this CipherChacha20poly1305) KeySize() int {
    return this.keySize
}

// 块大小
func (this CipherChacha20poly1305) BlockSize() int {
    return this.nonceSize
}

// 名称
func (this CipherChacha20poly1305) Name() string {
    return this.identifier
}

// 加密
func (this CipherChacha20poly1305) Encrypt(key, plaintext []byte) ([]byte, error) {
    nonce := key[this.keySize : this.keySize+this.nonceSize]

    aead, err := chacha20poly1305.New(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    return ciphertext, nil
}

// 解密
func (this CipherChacha20poly1305) Decrypt(key, ciphertext []byte) ([]byte, error) {
    nonce := key[this.keySize : this.keySize+this.nonceSize]

    aead, err := chacha20poly1305.New(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}
