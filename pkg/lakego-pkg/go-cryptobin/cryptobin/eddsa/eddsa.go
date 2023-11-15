package eddsa

import (
    "crypto"
    "crypto/ed25519"
)

type (
    // 设置
    Options = ed25519.Options
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

    // 设置
    options *Options

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    parsedData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewEdDSA() EdDSA {
    return EdDSA{
        options: &Options{
            Hash:    crypto.Hash(0),
            Context: "",
        },
        verify:  false,
        Errors:  make([]error, 0),
    }
}

// 构造函数
func New() EdDSA {
    return NewEdDSA()
}

var (
    // 默认
    defaultEdDSA = NewEdDSA()
)
