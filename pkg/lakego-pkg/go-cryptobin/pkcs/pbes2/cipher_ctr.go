package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// ctr 模式加密参数
type ctrParams []byte

// ctr 模式加密
type CipherCTR struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needPassBmp  bool
}

// 值大小
func (this CipherCTR) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCTR) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherCTR) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherCTR) NeedPasswordBmpString() bool {
    return this.needPassBmp
}

// 加密
func (this CipherCTR) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    // 随机生成 iv
    iv := make(ctrParams, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate IV: " + err.Error())
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    mode := cipher.NewCTR(block, iv)
    mode.XORKeyStream(encrypted, plaintext)

    // 编码 iv
    paramBytes, err := asn1.Marshal(iv)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherCTR) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析出 iv
    var iv ctrParams
    if _, err := asn1.Unmarshal(params, &iv); err != nil {
        return nil, errors.New("pkcs/cipher: invalid iv parameters")
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(iv) != blockSize {
        return nil, errors.New("pkcs/cipher: incorrect IV size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCTR(block, iv)
    mode.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// 设置 keySize
func (this CipherCTR) WithKeySize(keySize int) CipherCTR {
    this.keySize = keySize

    return this
}

func (this CipherCTR) WithHasKeyLength(hasKeyLength bool) CipherCTR {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherCTR) WithNeedPasswordBmpString(needPassBmp bool) CipherCTR {
    this.needPassBmp = needPassBmp

    return this
}
