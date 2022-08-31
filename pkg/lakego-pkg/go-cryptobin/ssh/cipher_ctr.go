package ssh

import (
    "crypto/cipher"

    "github.com/pkg/errors"
)

// CTR 模式加密
type CipherCTR struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier string
}

// 值大小
func (this CipherCTR) KeySize() int {
    return this.keySize
}

// 块大小
func (this CipherCTR) BlockSize() int {
    return this.blockSize
}

// 名称
func (this CipherCTR) Name() string {
    return this.identifier
}

// 加密
func (this CipherCTR) Encrypt(key, plaintext []byte) ([]byte, error) {
    // Add padding until the private key block matches the block size,
    // 16 with AES encryption, 8 without.
    for i, l := 0, len(plaintext); (l+i)%this.blockSize != 0; i++ {
        plaintext = append(plaintext, byte(i+1))
    }

    dst := make([]byte, len(plaintext))

    iv := key[this.keySize : this.keySize+this.blockSize]

    block, err := this.cipherFunc(key[:this.keySize])
    if err != nil {
        return nil, errors.Wrap(err, "error creating cipher")
    }

    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(dst, plaintext)

    return dst, nil
}

// 解密
func (this CipherCTR) Decrypt(key, ciphertext []byte) ([]byte, error) {
    dst := make([]byte, len(ciphertext))

    iv := key[this.keySize : this.keySize+this.blockSize]

    block, err := this.cipherFunc(key[:this.keySize])
    if err != nil {
        return nil, errors.Wrap(err, "error creating cipher")
    }

    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(dst, ciphertext)

    return dst, nil
}
