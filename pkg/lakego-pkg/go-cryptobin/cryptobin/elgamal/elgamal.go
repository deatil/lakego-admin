package elgamal

import (
    "hash"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/pubkey/elgamal"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

/**
 * ElGamal
 *
 * @create 2023-6-22
 * @author deatil
 */
type ElGamal struct {
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
    parsedData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewElGamal() ElGamal {
    return ElGamal{
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() ElGamal {
    return NewElGamal()
}

var (
    // 默认
    defaultElGamal = NewElGamal()
)
