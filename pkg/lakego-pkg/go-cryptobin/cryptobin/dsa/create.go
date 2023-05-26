package dsa

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
    cryptobin_dsa "github.com/deatil/go-cryptobin/dsa"
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
// dsa := New().GenerateKey("L2048N256")
// priKey := dsa.CreatePrivateKey().ToKeyString()
func (this DSA) CreatePrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_dsa.MarshalPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "DSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this DSA) CreatePrivateKeyWithPassword(password string, opts ...string) DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: privateKey error.")
        return this.AppendError(err)
    }

    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 加密方式
    cipher, err := cryptobin_tool.GetPEMCipher(opt)
    if err != nil {
        err := errors.New("dsa: PEMCipher not exists.")
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := cryptobin_dsa.MarshalPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := x509.EncryptPEMBlock(
        rand.Reader,
        "DSA PRIVATE KEY",
        x509PrivateKey,
        []byte(password),
        cipher,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成公钥 pem 数据
func (this DSA) CreatePublicKey() DSA {
    if this.publicKey == nil {
        err := errors.New("dsa: publicKey error.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := cryptobin_dsa.MarshalPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "DSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// ==========

// 生成 pkcs8 私钥 pem 数据
func (this DSA) CreatePKCS8PrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_dsa.MarshalPKCS8PrivateKey(this.privateKey)
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
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this DSA) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) DSA {
    if this.privateKey == nil {
        err := errors.New("DSA: privateKey error.")
        return this.AppendError(err)
    }

    opt, err := cryptobin_pkcs8s.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := cryptobin_dsa.MarshalPKCS8PrivateKey(this.privateKey)
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
func (this DSA) CreatePKCS8PublicKey() DSA {
    if this.publicKey == nil {
        err := errors.New("dsa: publicKey error.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := cryptobin_dsa.MarshalPKCS8PublicKey(this.publicKey)
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

