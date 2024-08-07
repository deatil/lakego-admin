package ecdsa

import (
    "hash"
    "crypto/ecdsa"
    "crypto/elliptic"
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
 * ECDSA
 *
 * @create 2022-4-3
 * @author deatil
 */
type ECDSA struct {
    // 私钥
    privateKey *ecdsa.PrivateKey

    // 公钥
    publicKey *ecdsa.PublicKey

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
func NewECDSA() ECDSA {
    return ECDSA{
        curve:    elliptic.P256(),
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() ECDSA {
    return NewECDSA()
}

var (
    // 默认
    defaultECDSA = NewECDSA()
)
