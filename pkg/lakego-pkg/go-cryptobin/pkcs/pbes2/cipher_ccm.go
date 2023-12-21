package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/cipher/ccm"
)

// ccm 模式加密参数
// http://javadoc.iaik.tugraz.at/iaik_jce/current/index.html?iaik/security/cipher/CCMParameters.html
// This class represents CCM parameters. The parameters specified for the CCM algorithm in RFC 5084 consist of the nonce and the length of the MAC (ICVlen):
// CCMParameters ::= SEQUENCE {
//         aes-nonce         OCTET STRING (SIZE(7..13)),
//         aes-ICVlen        AES-CCM-ICVlen DEFAULT 12 }
type ccmParams struct {
    Nonce  []byte
    ICVLen int `asn1:"default:12,optional"`
}

// ccm 模式加密
type CipherCCM struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    nonceSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needPassBmp  bool
}

// 值大小
func (this CipherCCM) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCCM) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherCCM) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherCCM) NeedPasswordBmpString() bool {
    return this.needPassBmp
}

// 加密
func (this CipherCCM) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
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
            return nil, errors.New("pkcs/cipher: invalid param type")
        }
    } else {
        nonce = params.Nonce
    }

    aead, err := ccm.NewCCMWithNonceSize(block, len(nonce))
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

func (this CipherCCM) WithHasKeyLength(hasKeyLength bool) CipherCCM {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherCCM) WithNeedPasswordBmpString(needPassBmp bool) CipherCCM {
    this.needPassBmp = needPassBmp

    return this
}
