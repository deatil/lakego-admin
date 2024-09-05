package curve25519

import (
    "github.com/deatil/go-cryptobin/pubkey/dh/curve25519"
)

/**
 * curve25519
 *
 * @create 2022-8-7
 * @author deatil
 */
type Curve25519 struct {
    // 私钥
    privateKey *curve25519.PrivateKey

    // 公钥
    publicKey *curve25519.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 密码数据
    secretData []byte

    // 错误
    Errors []error
}

// 构造函数
func NewCurve25519() Curve25519 {
    return Curve25519{
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() Curve25519 {
    return NewCurve25519()
}

var (
    // 默认
    defaultCurve25519 = NewCurve25519()
)
