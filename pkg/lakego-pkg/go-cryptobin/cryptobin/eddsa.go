package cryptobin

import (
    "crypto/ed25519"
)

// 构造函数
func NewEdDSA() EdDSA {
    return EdDSA{
        veryed: false,
    }
}

/**
 * EdDSA
 *
 * @create 2022-4-3
 * @author deatil
 */
type EdDSA struct {
    // 私钥
    privateKey ed25519.PrivateKey

    // 公钥
    publicKey ed25519.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    paredData []byte

    // 验证后情况
    veryed bool

    // 错误
    Error error
}
