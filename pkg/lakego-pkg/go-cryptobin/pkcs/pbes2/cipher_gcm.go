package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// gcm 模式加密参数
// GCM mode cipher Parameters
// http://javadoc.iaik.tugraz.at/iaik_jce/current/index.html?iaik/security/cipher/GCMParameters.html
// GCMParameters ::= SEQUENCE {
// 	aes-nonce        OCTET STRING, -- recommended size is 12 octets
// 	aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
type gcmParams struct {
    Nonce  []byte
    ICVLen int `asn1:"default:12,optional"`
}

// gcm 模式加密
type CipherGCM struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    nonceSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needBmpPass  bool
}

// 值大小
func (this CipherGCM) KeySize() int {
    return this.keySize
}

// oid
func (this CipherGCM) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherGCM) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherGCM) NeedBmpPassword() bool {
    return this.needBmpPass
}

// 加密
func (this CipherGCM) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
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
            return nil, errors.New("pkcs/cipher: invalid param type")
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
            return nil, errors.New("pkcs/cipher: invalid tag size")
        }
    }

    return aead.Open(nil, nonce, ciphertext, nil)
}

// 设置 keySize
func (this CipherGCM) WithKeySize(keySize int) CipherGCM {
    this.keySize = keySize

    return this
}

func (this CipherGCM) WithHasKeyLength(hasKeyLength bool) CipherGCM {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherGCM) WithNeedBmpPassword(needBmpPass bool) CipherGCM {
    this.needBmpPass = needBmpPass

    return this
}
