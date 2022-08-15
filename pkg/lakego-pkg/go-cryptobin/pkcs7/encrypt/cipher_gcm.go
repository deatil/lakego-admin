package encrypt

import (
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// gcm 模式加密参数
// http://javadoc.iaik.tugraz.at/iaik_jce/current/index.html?iaik/security/cipher/GCMParameters.html
type gcmParams struct {
    Nonce  []byte `asn1:"tag:4"`
    ICVLen int
}

// gcm 模式加密
type CipherGCM struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    nonceSize  int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherGCM) KeySize() int {
    return this.keySize
}

// oid
func (this CipherGCM) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherGCM) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
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
    paramSeq := gcmParams{
        Nonce:  nonce,
        ICVLen: aead.Overhead(),
    }

    // 编码参数
    paramBytes, err := asn1.Marshal(paramSeq)
    if err != nil {
        return nil, nil, err
    }

    return ciphertext, paramBytes, nil
}

// 解密
func (this CipherGCM) Decrypt(key, param, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    var nonce []byte

    isGcmICV := true

    // 解析参数
    var params gcmParams
    _, err = asn1.Unmarshal(param, &params)
    if err != nil {
        isGcmICV = false

        _, err = asn1.Unmarshal(param, &nonce)
        if err != nil {
            return nil, errors.New("pkcs8: invalid param type")
        }
    } else {
        nonce = params.Nonce
    }

    aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
    if err != nil {
        return nil, err
    }

    if isGcmICV {
        if params.ICVLen != aead.Overhead() {
            return nil, errors.New("pkcs8: invalid tag size")
        }
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}
