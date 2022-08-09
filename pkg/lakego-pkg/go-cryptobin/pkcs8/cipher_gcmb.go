package pkcs8

import (
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// gcm 模式加密参数, 使用 iv 位置
type gcmbParams []byte

// gcm 模式加密
type CipherGCMb struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    nonceSize  int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherGCMb) KeySize() int {
    return this.keySize
}

// oid
func (this CipherGCMb) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherGCMb) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, err
    }

    nonce, err := genRandom(this.nonceSize)
    if err != nil {
        return nil, nil, err
    }

    aead, err := cipher.NewGCMWithNonceSize(block, this.nonceSize)
    if err != nil {
        return nil, nil, err
    }

    // 加密数据
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // 需要编码的参数
    paramSeq := nonce

    // 编码参数
    paramBytes, err := asn1.Marshal(paramSeq)
    if err != nil {
        return nil, nil, err
    }

    return ciphertext, paramBytes, nil
}

// 解密
func (this CipherGCMb) Decrypt(key, param, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // 解析参数
    var nonce gcmbParams
    _, err = asn1.Unmarshal(param, &nonce)
    if err != nil {
        return nil, errors.New("pkcs8: invalid param type")
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
    if err != nil {
        return nil, err
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}
