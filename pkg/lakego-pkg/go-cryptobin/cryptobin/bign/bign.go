package bign

import (
    "hash"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/hash/belt"
    "github.com/deatil/go-cryptobin/pubkey/bign"
    ecbign "github.com/deatil/go-cryptobin/elliptic/bign"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

// marshal data type
type EncodingType uint

const (
    EncodingASN1 EncodingType = 1 + iota
    EncodingBytes
)

/**
 * Bign
 *
 * @create 2024-10-29
 * @author deatil
 */
type Bign struct {
    // 私钥
    privateKey *bign.PrivateKey

    // 公钥
    publicKey *bign.PublicKey

    // 生成类型
    curve elliptic.Curve

    // 签名验证类型
    signHash HashFunc

    // 数据编码方式
    encoding EncodingType

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 传入 adata 数据
    adata []byte

    // 解析后的数据
    parsedData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewBign() Bign {
    return Bign{
        curve:    ecbign.P256v1(),
        signHash: belt.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Bign {
    return NewBign()
}

var (
    // 默认
    defaultBign = NewBign()
)
