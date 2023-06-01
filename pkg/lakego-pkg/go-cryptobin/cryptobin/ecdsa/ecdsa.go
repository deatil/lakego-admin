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

/**
 * Ecdsa
 *
 * @create 2022-4-3
 * @author deatil
 */
type Ecdsa struct {
    // 私钥
    privateKey *ecdsa.PrivateKey

    // 公钥
    publicKey *ecdsa.PublicKey

    // 生成类型
    curve elliptic.Curve

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
func NewEcdsa() Ecdsa {
    return Ecdsa{
        curve:    elliptic.P256(),
        signHash: sha256.New,
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Ecdsa {
    return NewEcdsa()
}
