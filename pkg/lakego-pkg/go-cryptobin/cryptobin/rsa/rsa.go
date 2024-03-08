package rsa

import (
    "hash"
    "crypto"
    "crypto/rsa"
    "crypto/sha1"
)

/**
 * RSA 加密
 *
 * @create 2021-8-28
 * @author deatil
 */
type RSA struct {
    // 私钥
    privateKey *rsa.PrivateKey

    // 公钥
    publicKey *rsa.PublicKey

    // 签名验证类型
    signHash crypto.Hash

    // EncryptOAEP hash.Hash
    oaepHash hash.Hash

    // EncryptOAEP label
    oaepLabel []byte

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
func NewRSA() RSA {
    return RSA{
        signHash: crypto.SHA256,
        oaepHash: sha1.New(),
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() RSA {
    return NewRSA()
}

var (
    // 默认
    defaultRSA = NewRSA()
)
