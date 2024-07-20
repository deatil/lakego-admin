package dsa

import (
    "hash"
    "crypto/dsa"
    "crypto/sha256"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

// 数据编码方式
// marshal data type
type EncodingType uint

const (
    EncodingASN1 EncodingType = 1 + iota
    EncodingBytes
)

/**
 * DSA
 *
 * @create 2022-7-25
 * @author deatil
 */
type DSA struct {
    // 私钥
    privateKey *dsa.PrivateKey

    // 公钥
    publicKey *dsa.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    parsedData []byte

    // 签名验证类型
    signHash HashFunc

    // 数据编码方式
    encoding EncodingType

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewDSA() DSA {
    return DSA{
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() DSA {
    return NewDSA()
}

var (
    // 默认
    defaultDSA = NewDSA()
)
