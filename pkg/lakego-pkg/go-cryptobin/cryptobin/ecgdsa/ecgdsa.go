package ecgdsa

import (
    "hash"
    "crypto/elliptic"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/pubkey/ecgdsa"
)

type (
    // HashFunc
    HashFunc = func() hash.Hash
)

// encoding data type
type EncodingType uint

const (
    EncodingASN1 EncodingType = 1 + iota
    EncodingBytes
)

/**
 * EC-GDSA
 *
 * @create 2024-9-26
 * @author deatil
 */
type ECGDSA struct {
    // 私钥
    privateKey *ecgdsa.PrivateKey

    // 公钥
    publicKey *ecgdsa.PublicKey

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
func NewECGDSA() ECGDSA {
    return ECGDSA{
        curve:    elliptic.P256(),
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() ECGDSA {
    return NewECGDSA()
}

var (
    // 默认
    defaultECGDSA = NewECGDSA()
)
