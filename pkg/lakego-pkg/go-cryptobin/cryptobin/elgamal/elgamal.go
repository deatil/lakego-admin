package elgamal

import (
    "hash"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/elgamal"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

/**
 * EIGamal
 *
 * @create 2023-6-22
 * @author deatil
 */
type EIGamal struct {
    // 私钥
    privateKey *elgamal.PrivateKey

    // 公钥
    publicKey *elgamal.PublicKey

    // 签名验证类型
    signHash HashFunc

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
func NewEIGamal() EIGamal {
    return EIGamal{
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() EIGamal {
    return NewEIGamal()
}

var (
    // 默认
    defaultEIGamal = NewEIGamal()
)
