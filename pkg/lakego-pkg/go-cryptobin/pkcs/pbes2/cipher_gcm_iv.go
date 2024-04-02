package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// gcm 模式加密参数, 使用 iv 位置
type gcmIvParams []byte

// gcm 模式加密
type CipherGCMIv struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    nonceSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needPassBmp  bool
}

// 值大小
func (this CipherGCMIv) KeySize() int {
    return this.keySize
}

// oid
func (this CipherGCMIv) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherGCMIv) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherGCMIv) NeedPasswordBmpString() bool {
    return this.needPassBmp
}

// 加密
func (this CipherGCMIv) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, err
    }

    nonce := make([]byte, this.nonceSize)
    if _, err := io.ReadFull(rand, nonce); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate nonce: " + err.Error())
    }

    aead, err := cipher.NewGCMWithNonceSize(block, this.nonceSize)
    if err != nil {
        return nil, nil, err
    }

    // 加密数据
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // 需要编码的参数
    paramSeq := gcmIvParams(nonce)

    // 编码参数
    paramBytes, err := asn1.Marshal(paramSeq)
    if err != nil {
        return nil, nil, err
    }

    return ciphertext, paramBytes, nil
}

// 解密
func (this CipherGCMIv) Decrypt(key, param, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // 解析参数
    var nonce gcmIvParams
    _, err = asn1.Unmarshal(param, &nonce)
    if err != nil {
        return nil, errors.New("pkcs/cipher: invalid param type")
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}

// 设置 keySize
func (this CipherGCMIv) WithKeySize(keySize int) CipherGCMIv {
    this.keySize = keySize

    return this
}

func (this CipherGCMIv) WithHasKeyLength(hasKeyLength bool) CipherGCMIv {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherGCMIv) WithNeedPasswordBmpString(needPassBmp bool) CipherGCMIv {
    this.needPassBmp = needPassBmp

    return this
}
