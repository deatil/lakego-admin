package cryptobin

import (
    "crypto/ecdsa"
    "crypto/elliptic"
)

// 构造函数
func NewEcdsa() Ecdsa {
    return Ecdsa{
        curve: elliptic.P256(),
        signHash: "SHA512",
        veryed: false,
    }
}

/**
 * Ecdsa 加密
 *
 * @create 2022-4-3
 * @author deatil
 */
type Ecdsa struct {
    // 私钥
    privateKey *ecdsa.PrivateKey

    // 公钥
    publicKey *ecdsa.PublicKey

    // 生成类型
    curve elliptic.Curve

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    paredData []byte

    // 签名验证类型
    signHash string

    // 验证后情况
    veryed bool

    // 错误
    Error error
}

// 设置 PrivateKey
func (this Ecdsa) WithPrivateKey(data *ecdsa.PrivateKey) Ecdsa {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Ecdsa) WithPublicKey(data *ecdsa.PublicKey) Ecdsa {
    this.publicKey = data

    return this
}

// 设置 data
// 可选 [P521 | P384 | P256 | P224]
func (this Ecdsa) WithCurve(hash string) Ecdsa {
    var curve elliptic.Curve

    if hash == "P521" {
        curve = elliptic.P521()
    } else if hash == "P384" {
        curve = elliptic.P384()
    } else if hash == "P256" {
        curve = elliptic.P256()
    } else if hash == "P224" {
        curve = elliptic.P224()
    }

    this.curve = curve

    return this
}

// 设置 data
func (this Ecdsa) WithData(data []byte) Ecdsa {
    this.data = data

    return this
}

// 设置 paredData
func (this Ecdsa) WithParedData(data []byte) Ecdsa {
    this.paredData = data

    return this
}

// 设置 hash 类型
func (this Ecdsa) WithSignHash(data string) Ecdsa {
    this.signHash = data

    return this
}

// 设置错误
func (this Ecdsa) WithError(err error) Ecdsa {
    this.Error = err

    return this
}
