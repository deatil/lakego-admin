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
