package ssh

import (
    "errors"
    "crypto/cipher"
)

// cbc 模式加密
type CipherCBC struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier string
}

// 值大小
func (this CipherCBC) KeySize() int {
    return this.keySize
}

// 块大小
func (this CipherCBC) BlockSize() int {
    return this.blockSize
}

// oid
func (this CipherCBC) Name() string {
    return this.identifier
}

// 加密
func (this CipherCBC) Encrypt(key, plaintext []byte) ([]byte, error) {
    // Add padding until the private key block matches the block size,
    // 16 with AES encryption, 8 without.
    for i, l := 0, len(plaintext); (l+i)%this.blockSize != 0; i++ {
        plaintext = append(plaintext, byte(i+1))
    }

    iv := key[this.keySize : this.keySize+this.blockSize]

    block, err := this.cipherFunc(key[:this.keySize])
    if err != nil {
        return nil, errors.New("ssh:" + err.Error() + " failed to create cipher")
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    return encrypted, nil
}

// 解密
func (this CipherCBC) Decrypt(key, ciphertext []byte) ([]byte, error) {
    iv := key[this.keySize : this.keySize+this.blockSize]

    plaintext := make([]byte, len(ciphertext))

    block, err := this.cipherFunc(key[:this.keySize])
    if err != nil {
        return nil, err
    }

    // 判断数据是否为填充数据
    blockSize := block.BlockSize()
    dlen := len(ciphertext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("ssh: invalid padding")
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    return plaintext, nil
}
