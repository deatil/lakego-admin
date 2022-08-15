package encrypt

import (
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

// ccm 模式加密参数
// http://javadoc.iaik.tugraz.at/iaik_jce/current/index.html?iaik/security/cipher/CCMParameters.html
type ccmParams struct {
    Nonce  []byte `asn1:"tag:4"`
    ICVLen int
}

// ccm 模式加密
type CipherCCM struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    nonceSize  int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherCCM) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCCM) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherCCM) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, err
    }

    nonce, err := genRandom(this.nonceSize)
    if err != nil {
        return nil, nil, err
    }

    aead, err := cryptobin_cipher.NewCCMWithNonceSize(block, this.nonceSize)
    if err != nil {
        return nil, nil, err
    }

    // 加密数据
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // 需要编码的参数
    paramSeq := ccmParams{
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
func (this CipherCCM) Decrypt(key, param, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    var nonce []byte

    isGcmICV := true

    // 解析参数
    var params ccmParams
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

    aead, err := cryptobin_cipher.NewCCMWithNonceSize(block, len(nonce))
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
