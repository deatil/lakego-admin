package cryptobin

import (
    "crypto/rsa"
    "crypto/x509"
)

// 构造函数
func NewRsa() Rsa {
    return Rsa{
        veryed:   false,
        signHash: "SHA512",
    }
}

// pem 加密方式
var PEMCiphers = map[string]x509.PEMCipher{
    "DESCBC":     x509.PEMCipherDES,
    "DESEDE3CBC": x509.PEMCipher3DES,
    "AES128CBC":  x509.PEMCipherAES128,
    "AES192CBC":  x509.PEMCipherAES192,
    "AES256CBC":  x509.PEMCipherAES256,
}

/**
 * Rsa 加密
 *
 * @create 2021-8-28
 * @author deatil
 */
type Rsa struct {
    // 私钥
    privateKey *rsa.PrivateKey

    // 公钥
    publicKey *rsa.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    paredData []byte

    // 验证后情况
    veryed bool

    // 签名验证类型
    signHash string

    // 错误
    Error error
}

// 设置 PrivateKey
func (this Rsa) WithPrivateKey(data *rsa.PrivateKey) Rsa {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Rsa) WithPublicKey(data *rsa.PublicKey) Rsa {
    this.publicKey = data

    return this
}

// 设置 data
func (this Rsa) WithData(data []byte) Rsa {
    this.data = data

    return this
}

// 设置 paredData
func (this Rsa) WithParedData(data []byte) Rsa {
    this.paredData = data

    return this
}

// 设置 hash 类型
func (this Rsa) WithSignHash(data string) Rsa {
    this.signHash = data

    return this
}

// 设置错误
func (this Rsa) WithError(err error) Rsa {
    this.Error = err

    return this
}
