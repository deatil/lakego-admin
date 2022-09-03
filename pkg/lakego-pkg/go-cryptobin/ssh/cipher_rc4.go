package ssh

import (
    "crypto/rc4"
)

// CipherRC4 加密/解密
type CipherRC4 struct {
    keySize    int
    blockSize  int
    identifier string
}

// 设置值大小
func (this CipherRC4) WithKeySize(keySize int) CipherRC4 {
    this.keySize = keySize

    return this
}

// 值大小
func (this CipherRC4) KeySize() int {
    return this.keySize
}

// 块大小
func (this CipherRC4) BlockSize() int {
    return this.blockSize
}

// 名称
func (this CipherRC4) Name() string {
    return this.identifier
}

// 加密
func (this CipherRC4) Encrypt(key, plaintext []byte) ([]byte, error) {
    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, err
    }

    ciphertext := make([]byte, len(plaintext))
    cipher.XORKeyStream(ciphertext, plaintext)

    return ciphertext, nil
}

// 解密
func (this CipherRC4) Decrypt(key, ciphertext []byte) ([]byte, error) {
    cipher, err := rc4.NewCipher(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))
    cipher.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}
