package ecdh

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/ecdh"
    ecdh_key "github.com/deatil/go-cryptobin/ecdh/key"
)

type (
    // 配置
    Opts       = pkcs8.Opts
    // PBKDF2 配置
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = pkcs8.ScryptOpts
)

var (
    // 获取 Cipher 类型
    GetCipherFromName = pkcs8.GetCipherFromName
    // 获取 hash 类型
    GetHashFromName   = pkcs8.GetHashFromName
)

// 生成私钥 pem 数据
// 使用:
// obj := New().SetCurve("P256").GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this ECDH) CreatePrivateKey() ECDH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this ECDH) CreatePrivateKeyWithPassword(password string, opts ...any) ECDH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKeyBytes,
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
func (this ECDH) CreatePublicKey() ECDH {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := x509.MarshalPKIXPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// =======================

// 生成私钥 pem 数据, 库自使用的 asn1 格式
func (this ECDH) CreateECDHPrivateKey() ECDH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    privateKey, err := ecdh.FromPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateKeyBytes, err := ecdh_key.MarshalPrivateKey(privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据, 库自使用的 asn1 格式
func (this ECDH) CreateECDHPrivateKeyWithPassword(password string, opts ...any) ECDH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    privateKey, err := ecdh.FromPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := ecdh_key.MarshalPrivateKey(privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs8.EncryptPEMBlock(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        opt,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成公钥 pem 数据, 库自使用的 asn1 格式
func (this ECDH) CreateECDHPublicKey() ECDH {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    publicKey, err := ecdh.FromPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicKeyBytes, err := ecdh_key.MarshalPublicKey(publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// =======================

// 根据公钥和私钥生成对称密钥
func (this ECDH) CreateSecretKey() ECDH {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    secretKey, err := this.privateKey.ECDH(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.secretData = secretKey

    return this
}
