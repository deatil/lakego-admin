package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
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

// 生成私钥 pem 数据, PKCS1 别名
// 使用:
// obj := New().GenerateKey(2048)
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this Rsa) CreatePrivateKey() Rsa {
    return this.CreatePKCS1PrivateKey()
}

// 生成私钥带密码 pem 数据, PKCS1 别名
func (this Rsa) CreatePrivateKeyWithPassword(password string, opts ...string) Rsa {
    return this.CreatePKCS1PrivateKeyWithPassword(password, opts...)
}

// 生成 PKCS1 私钥
func (this Rsa) CreatePKCS1PrivateKey() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("Rsa: [CreatePKCS1PrivateKey()] privateKey error.")
        return this
    }

    x509PrivateKey := x509.MarshalPKCS1PrivateKey(this.privateKey)

    privateBlock := &pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS1 私钥带密码 pem 数据
// CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC")
func (this Rsa) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("Rsa: [CreatePKCS1PrivateKeyWithPassword()] privateKey error.")
        return this
    }

    // DESCBC | DESEDE3CBC | AES128CBC
    // AES192CBC | AES256CBC
    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 具体方式
    cipher, ok := PEMCiphers[opt]
    if !ok {
        this.Error = errors.New("Rsa: [CreatePKCS1PrivateKeyWithPassword()] PEMCipher not exists.")
        return this
    }

    // 生成私钥
    x509PrivateKey := x509.MarshalPKCS1PrivateKey(this.privateKey)

    // 生成加密数据
    privateBlock, err := x509.EncryptPEMBlock(
        rand.Reader,
        "RSA PRIVATE KEY",
        x509PrivateKey,
        []byte(password),
        cipher,
    )
    if err != nil {
        this.Error = err
        return this
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥 pem 数据
func (this Rsa) CreatePKCS8PrivateKey() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("Rsa: [CreatePKCS8PrivateKey()] privateKey error.")
        return this
    }

    x509PublicKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: x509PublicKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this Rsa) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("Rsa: [CreatePKCS8PrivateKeyWithPassword()] privateKey error.")
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
func (this Rsa) CreatePublicKey() Rsa {
    var publicKey *rsa.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("Rsa: [CreatePublicKey()] privateKey error.")

            return this
        }

        publicKey = &this.privateKey.PublicKey
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
