package ed448

import (
    "crypto"

    "github.com/deatil/go-cryptobin/ed448"
)

type (
    // 设置
    Options = ed448.Options
)

const (
    SchemeED448   = ed448.ED448
    SchemeED448Ph = ed448.ED448Ph
)

/**
 * ED448
 *
 * @create 2023-10-25
 * @author deatil
 */
type ED448 struct {
    // 私钥
    privateKey ed448.PrivateKey

    // 公钥
    publicKey ed448.PublicKey

    // 设置
    options *Options

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
func NewED448() ED448 {
    return ED448{
        options: &Options{
            Hash:    crypto.Hash(0),
            Context: "",
            Scheme:  SchemeED448,
        },
        verify:  false,
        Errors:  make([]error, 0),
    }
}

// 构造函数
func New() ED448 {
    return NewED448()
}

var (
    // 默认
    defaultED448 = NewED448()
)
