package bip0340

import (
    "hash"
    "crypto/elliptic"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/pubkey/bip0340"
    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
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
 * BIP0340
 *
 * @create 2024-12-24
 * @author deatil
 */
type BIP0340 struct {
    // 私钥
    privateKey *bip0340.PrivateKey

    // 公钥
    publicKey *bip0340.PublicKey

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

    // 解析后的数据
    parsedData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewBIP0340() BIP0340 {
    return BIP0340{
        curve:    secp256k1.S256(),
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() BIP0340 {
    return NewBIP0340()
}

var (
    // 默认
    defaultBIP0340 = NewBIP0340()
)
