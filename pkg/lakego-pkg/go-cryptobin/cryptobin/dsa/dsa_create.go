package dsa

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    cryptobin_dsa "github.com/deatil/go-cryptobin/dsa"
    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
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
// dsa := New().GenerateKey("L2048N256")
// priKey := dsa.CreatePrivateKey().ToKeyString()
func (this DSA) CreatePrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: [CreatePrivateKey()] privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_dsa.MarshalPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type: "DSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC")
func (this DSA) CreatePrivateKeyWithPassword(password string, opts ...string) DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: [CreatePrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
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
        err := errors.New("dsa: [CreatePrivateKeyWithPassword()] PEMCipher not exists.")
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
        err := errors.New("dsa: [CreatePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := cryptobin_dsa.MarshalPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type: "DSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// ==========

// 生成 pkcs8 私钥 pem 数据
func (this DSA) CreatePKCS8PrivateKey() DSA {
    if this.privateKey == nil {
        err := errors.New("dsa: [CreatePKCS8PrivateKey()] privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_dsa.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this DSA) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) DSA {
    if len(opts) > 0 {
        switch optString := opts[0].(type) {
            case string:
                isPkcs8Pbe := cryptobin_pkcs8pbe.CheckCipherFromName(optString)

                if isPkcs8Pbe {
                    return this.CreatePKCS8PbePrivateKeyWithPassword(password, optString)
                }
        }
    }

    return this.CreatePKCS8KdfPrivateKeyWithPassword(password, opts...)
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePKCS8KdfPrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this DSA) CreatePKCS8KdfPrivateKeyWithPassword(password string, opts ...any) DSA {
    if this.privateKey == nil {
        err := errors.New("DSA: [CreatePKCS8KdfPrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
    }

    opt, err := cryptobin_pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := cryptobin_dsa.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
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
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
func (this DSA) CreatePKCS8PbePrivateKeyWithPassword(password string, alg string) DSA {
    if this.privateKey == nil {
        err := errors.New("DSA: [CreatePKCS8PbePrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := cryptobin_dsa.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    pemCipher := cryptobin_pkcs8pbe.GetCipherFromName(alg)

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs8pbe.EncryptPKCS8PrivateKey(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        x509PrivateKey,
        []byte(password),
        pemCipher,
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
        err := errors.New("dsa: [CreatePKCS8PublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := cryptobin_dsa.MarshalPKCS8PublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type: "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

