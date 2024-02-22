package elgamal

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    cryptobin_elgamal "github.com/deatil/go-cryptobin/elgamal"
    cryptobin_pkcs1 "github.com/deatil/go-cryptobin/pkcs1"
    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
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
// elgamal := New().GenerateKey("L2048N256")
// priKey := elgamal.CreatePrivateKey().ToKeyString()
func (this EIGamal) CreatePrivateKey() EIGamal {
    return this.CreatePKCS1PrivateKey()
}

// 生成私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this EIGamal) CreatePrivateKeyWithPassword(password string, opts ...string) EIGamal {
    return this.CreatePKCS1PrivateKeyWithPassword(password, opts...)
}

// 生成公钥 pem 数据
func (this EIGamal) CreatePublicKey() EIGamal {
    return this.CreatePKCS1PublicKey()
}

// ==========

// 生成 pkcs1 私钥 pem 数据
func (this EIGamal) CreatePKCS1PrivateKey() EIGamal {
    if this.privateKey == nil {
        err := errors.New("elgamal: privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_elgamal.MarshalPKCS1PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "EIGamal PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 pkcs1 私钥带密码 pem 数据
// CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC")
// PEMCipher: DESCBC | DESEDE3CBC | AES128CBC | AES192CBC | AES256CBC
func (this EIGamal) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) EIGamal {
    if this.privateKey == nil {
        err := errors.New("elgamal: privateKey error.")
        return this.AppendError(err)
    }

    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 加密方式
    cipher := cryptobin_pkcs1.GetPEMCipher(opt)
    if cipher == nil {
        err := errors.New("elgamal: PEMCipher not exists.")
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := cryptobin_elgamal.MarshalPKCS1PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs1.EncryptPEMBlock(
        rand.Reader,
        "EIGamal PRIVATE KEY",
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

// 生成 pkcs1 公钥 pem 数据
func (this EIGamal) CreatePKCS1PublicKey() EIGamal {
    if this.publicKey == nil {
        err := errors.New("elgamal: publicKey error.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := cryptobin_elgamal.MarshalPKCS1PublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    publicBlock := &pem.Block{
        Type:  "EIGamal PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// ==========

// 生成 pkcs8 私钥 pem 数据
func (this EIGamal) CreatePKCS8PrivateKey() EIGamal {
    if this.privateKey == nil {
        err := errors.New("elgamal: privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_elgamal.MarshalPKCS8PrivateKey(this.privateKey)
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
func (this EIGamal) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) EIGamal {
    if this.privateKey == nil {
        err := errors.New("elgamal: privateKey error.")
        return this.AppendError(err)
    }

    opt, err := cryptobin_pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := cryptobin_elgamal.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs8.EncryptPEMBlock(
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
func (this EIGamal) CreatePKCS8PublicKey() EIGamal {
    if this.publicKey == nil {
        err := errors.New("elgamal: publicKey error.")
        return this.AppendError(err)
    }

    publicKeyBytes, err := cryptobin_elgamal.MarshalPKCS8PublicKey(this.publicKey)
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
func (this EIGamal) CreateXMLPrivateKey() EIGamal {
    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    xmlPrivateKey, err := cryptobin_elgamal.MarshalXMLPrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = xmlPrivateKey

    return this
}

// 生成公钥 xml 数据
func (this EIGamal) CreateXMLPublicKey() EIGamal {
    if this.publicKey == nil {
        err := errors.New("publicKey error.")
        return this.AppendError(err)
    }

    xmlPublicKey, err := cryptobin_elgamal.MarshalXMLPublicKey(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = xmlPublicKey

    return this
}

