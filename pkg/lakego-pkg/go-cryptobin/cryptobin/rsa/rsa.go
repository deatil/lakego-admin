package rsa

import (
    "crypto/rsa"
)

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

    // 验证结果
    verify bool

    // 签名验证类型
    signHash string

    // 错误
    Errors []error
}

// 构造函数
func NewRsa() Rsa {
    return Rsa{
        signHash: "SHA512",
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Rsa {
    return NewRsa()
}

var (
    // 默认
    defaultRSA = NewRsa()
)
