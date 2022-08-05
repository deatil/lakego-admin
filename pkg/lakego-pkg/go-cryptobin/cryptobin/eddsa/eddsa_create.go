package eddsa

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "crypto/ed25519"
    "encoding/pem"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
)

type (
    // 配置
    Opts = cryptobin_pkcs8.Opts
    // PBKDF2 配置
    PBKDF2Opts = cryptobin_pkcs8.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = cryptobin_pkcs8.ScryptOpts
)

var (
    // 获取 Cipher 类型
    GetCipherFromName = cryptobin_pkcs8.GetCipherFromName
    // 获取 hash 类型
    GetHashFromName   = cryptobin_pkcs8.GetHashFromName
)

// 生成私钥 pem 数据
// 使用:
// obj := New().GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this EdDSA) CreatePrivateKey() EdDSA {
    if this.privateKey == nil {
        this.Error = errors.New("EdDSA: [CreatePrivateKey()] privateKey error.")
        return this
    }

    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this EdDSA) CreatePrivateKeyWithPassword(password string, opts ...any) EdDSA {
    if this.privateKey == nil {
        this.Error = errors.New("EdDSA: [CreatePrivateKeyWithPassword()] privateKey error.")
        return this
    }

    opt, err := cryptobin_pkcs8.ParseOpts(opts...)
    if err != nil {
        this.Error = err
        return this
    }

    // 生成私钥
    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs8.EncryptPKCS8PrivateKey(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        x509PrivateKey,
        []byte(password),
        opt,
    )
    if err != nil {
        this.Error = err
        return this
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成公钥 pem 数据
func (this EdDSA) CreatePublicKey() EdDSA {
    var publicKey ed25519.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("EdDSA: [CreatePublicKey()] privateKey error.")

            return this
        }

        publicKey = this.privateKey.Public().(ed25519.PublicKey)
    } else {
        publicKey = this.publicKey
    }

    x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        this.Error = err
        return this
    }

    publicBlock := &pem.Block{
        Type: "PUBLIC KEY",
        Bytes: x509PublicKey,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}
