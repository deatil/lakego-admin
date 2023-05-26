package eddsa

import (
    "crypto/ed25519"
)

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

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewEdDSA() EdDSA {
    return EdDSA{
        verify: false,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() EdDSA {
    return NewEdDSA()
}
