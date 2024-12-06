package elgamal

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
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
// elgamal := New().GenerateKey("L2048N256")
// priKey := elgamal.CreatePrivateKey().ToKeyString()
func (this ElGamal) CreatePrivateKey() ElGamal {
    return this.CreatePKCS1PrivateKey()
}

// 生成私钥带密码 pem 数据
func (this ElGamal) CreatePrivateKeyWithPassword(password string, opts ...string) ElGamal {
    return this.CreatePKCS1PrivateKeyWithPassword(password, opts...)
}

// 生成公钥 pem 数据
func (this ElGamal) CreatePublicKey() ElGamal {
    return this.CreatePKCS1PublicKey()
}

// ==========

// 生成 pkcs1 私钥 pem 数据
func (this ElGamal) CreatePKCS1PrivateKey() ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := elgamal.MarshalPKCS1PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "ElGamal PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 pkcs1 私钥带密码 pem 数据
// CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this ElGamal) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 加密方式
    cipher := pkcs1.GetPEMCipher(opt)
    if cipher == nil {
        err := errors.New("PEMCipher not exists.")
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := elgamal.MarshalPKCS1PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := pkcs1.EncryptPEMBlock(
        rand.Reader,
        "ElGamal PRIVATE KEY",
        privateKeyBytes,
        []byte(password),
        cipher,
    )
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 pkcs1 公钥 pem 数据
func (this ElGamal) CreatePKCS1PublicKey() ElGamal {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := elgamal.MarshalPKCS1PublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "ElGamal PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// ==========

// 生成 pkcs8 私钥 pem 数据
func (this ElGamal) CreatePKCS8PrivateKey() ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := elgamal.MarshalPKCS8PrivateKey(this.privateKey)
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
func (this ElGamal) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    opt, err := pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := elgamal.MarshalPKCS8PrivateKey(this.privateKey)
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
func (this ElGamal) CreatePKCS8PublicKey() ElGamal {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := elgamal.MarshalPKCS8PublicKey(this.publicKey)
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

// ====================

// 生成私钥 xml 数据
func (this ElGamal) CreateXMLPrivateKey() ElGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    xmlPrivateKey, err := elgamal.MarshalXMLPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = xmlPrivateKey

    return this
}

// 生成公钥 xml 数据
func (this ElGamal) CreateXMLPublicKey() ElGamal {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    xmlPublicKey, err := elgamal.MarshalXMLPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = xmlPublicKey

    return this
}

