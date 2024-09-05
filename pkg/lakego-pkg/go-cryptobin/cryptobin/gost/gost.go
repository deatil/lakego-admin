package gost

import (
    "hash"

    "github.com/deatil/go-cryptobin/pubkey/gost"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
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
 * Gost
 *
 * @create 2024-2-25
 * @author deatil
 */
type Gost struct {
    // 私钥
    privateKey *gost.PrivateKey

    // 公钥
    publicKey *gost.PublicKey

    // 生成类型
    curve *gost.Curve

    // 签名验证类型
    signHash HashFunc

    // 数据编码方式
    encoding EncodingType

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    parsedData []byte

    // 密码数据
    secretData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewGost() Gost {
    return Gost{
        curve:    gost.CurveDefault(),
        signHash: gost34112012256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Gost {
    return NewGost()
}

var (
    // 默认
    defaultGost = NewGost()
)
