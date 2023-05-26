package ecdh

import (
    "github.com/deatil/go-cryptobin/dh/ecdh"
)

/**
 * ecdh
 *
 * @create 2022-8-7
 * @author deatil
 */
type Ecdh struct {
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
func NewEcdh() Ecdh {
    curve := ecdh.P256()

    return Ecdh{
        curve: curve,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() Ecdh {
    return NewEcdh()
}
