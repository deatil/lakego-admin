package pkcs1

import (
    "io"
    "errors"
    "crypto/cipher"
)

// CTR 模式加密
type CipherCTR struct {
    // 对称加密
    cipherFunc     func(key []byte) (cipher.Block, error)
    // 密钥生成
    derivedKeyFunc func(password []byte, salt []byte, keySize int) []byte
    // salt 长度
    saltSize       int
    // 与 key 长度相关
    keySize        int
    // 与 iv 长度相关
    blockSize      int
    // name
    name           string
}

// 块大小
func (this CipherCTR) BlockSize() int {
    return this.blockSize
}

// 名称
func (this CipherCTR) Name() string {
    return this.name
}

// 加密
func (this CipherCTR) Encrypt(rand io.Reader, password, plaintext []byte) ([]byte, []byte, error) {
    iv := make([]byte, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs1: cannot generate IV: " + err.Error())
    }

    salt := iv[:this.saltSize]
    key := this.derivedKeyFunc(password, salt, this.keySize)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs1: failed to create cipher: " + err.Error())
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCTR(block, iv)
    enc.XORKeyStream(encrypted, plaintext)

    return encrypted, iv, nil
}

// 解密
func (this CipherCTR) Decrypt(password, iv, ciphertext []byte) ([]byte, error) {
    if len(iv) < this.saltSize {
        return nil, errors.New("go-cryptobin/pkcs1: iv length is too short")
    }

    salt := iv[:this.saltSize]
    key := this.derivedKeyFunc(password, salt, this.keySize)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCTR(block, iv)
    mode.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}
