package ecdh

import (
    "crypto/ecdh"
)

/**
 * ecdh
 * go 最低版本需要 `1.20rc1`。
 *
 * @create 2022-8-7
 * @author deatil
 */
type ECDH struct {
    // 私钥
    privateKey *ecdh.PrivateKey

    // 公钥
    publicKey *ecdh.PublicKey

    // 散列方式
    curve ecdh.Curve

    // [私钥/公钥]数据
    keyData []byte

    // 密码数据
    secretData []byte

    // 错误
    Errors []error
}

// 构造函数
func NewECDH() ECDH {
    return ECDH{
        curve:  ecdh.P256(),
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() ECDH {
    return NewECDH()
}

var (
    // 默认
    defaultECDH = NewECDH()
)
