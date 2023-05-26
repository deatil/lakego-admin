package eddsa

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8s "github.com/deatil/go-cryptobin/pkcs8s"
)

type (
    // 配置
    Opts       = cryptobin_pkcs8.Opts
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
        err := errors.New("EdDSA: privateKey error.")
        return this.AppendError(err)
    }

    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this EdDSA) CreatePrivateKeyWithPassword(password string, opts ...any) EdDSA {
    if this.privateKey == nil {
        err := errors.New("EdDSA: privateKey error.")
        return this.AppendError(err)
    }

    opt, err := cryptobin_pkcs8s.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs8s.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        x509PrivateKey,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成公钥 pem 数据
func (this EdDSA) CreatePublicKey() EdDSA {
    if this.publicKey == nil {
        err := errors.New("EdDSA: publicKey error.")
        return this.AppendError(err)
    }

    x509PublicKey, err := x509.MarshalPKIXPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: x509PublicKey,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}
