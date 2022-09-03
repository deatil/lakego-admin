package ssh

import (
    "crypto/cipher"
)

// gcm 模式加密
type CipherGCM struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    nonceSize  int
    identifier string
}

// 值大小
func (this CipherGCM) KeySize() int {
    return this.keySize
}

// 块大小
func (this CipherGCM) BlockSize() int {
    return this.nonceSize
}

// 名称
func (this CipherGCM) Name() string {
    return this.identifier
}

// 加密
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

    // 加密数据
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    return ciphertext, nil
}

// 解密
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
