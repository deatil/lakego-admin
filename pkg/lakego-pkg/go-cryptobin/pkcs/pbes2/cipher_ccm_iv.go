package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/cipher/ccm"
)

// ccm 模式加密参数
type ccmIvParams []byte

// ccm 模式加密
type CipherCCMIv struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    nonceSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needPassBmp  bool
}

// 值大小
func (this CipherCCMIv) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCCMIv) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherCCMIv) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherCCMIv) NeedPasswordBmpString() bool {
    return this.needPassBmp
}

// 加密
func (this CipherCCMIv) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, err
    }

    nonce := make([]byte, this.nonceSize)
    if _, err := io.ReadFull(rand, nonce); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate nonce: " + err.Error())
    }

    aead, err := ccm.NewCCMWithNonceSize(block, this.nonceSize)
    if err != nil {
        return nil, nil, err
    }

    // 加密数据
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // 需要编码的参数
    paramSeq := ccmIvParams(nonce)

    // 编码参数
    paramBytes, err := asn1.Marshal(paramSeq)
    if err != nil {
        return nil, nil, err
    }

    return ciphertext, paramBytes, nil
}

// 解密
func (this CipherCCMIv) Decrypt(key, param, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // 解析参数
    var nonce ccmIvParams
    _, err = asn1.Unmarshal(param, &nonce)
    if err != nil {
        return nil, errors.New("pkcs/cipher: invalid param type")
    }

    aead, err := ccm.NewCCMWithNonceSize(block, len(nonce))
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}

func (this CipherCCMIv) WithHasKeyLength(hasKeyLength bool) CipherCCMIv {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherCCMIv) WithNeedPasswordBmpString(needPassBmp bool) CipherCCMIv {
    this.needPassBmp = needPassBmp

    return this
}
