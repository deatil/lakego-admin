package sm2

import (
    "errors"
    "crypto/rand"
    "encoding/pem"
    crypto_x509 "crypto/x509"

    "github.com/tjfoc/gmsm/x509"

    cryptobin_sm2 "github.com/deatil/go-cryptobin/sm2"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
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

// 生成私钥 pem 数据，默认使用 PKCS8 编码
// 使用:
// obj := New().GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this SM2) CreatePrivateKey() SM2 {
    return this.CreatePKCS8PrivateKey()
}

// 生成私钥带密码 pem 数据
func (this SM2) CreatePrivateKeyWithPassword(password string, opts ...any) SM2 {
    if len(opts) == 0 {
        return this.CreateSM2PrivateKeyWithPassword(password)
    }

    return this.CreatePKCS8PrivateKeyWithPassword(password, opts...)
}

// ====================

// 生成私钥 pem 数据
func (this SM2) CreatePKCS1PrivateKey() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    privateKeyBytes, err := cryptobin_sm2.MarshalSM2PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    privateBlock := &pem.Block{
        Type:  "SM2 PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成私钥带密码 pem 数据
func (this SM2) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // 加密方式
    cipher, err := cryptobin_tool.GetPEMCipher(opt)
    if err != nil {
        err := errors.New("SM2: PEMCipher not exists.")
        return this.AppendError(err)
    }

    // 生成私钥
    privateKeyBytes, err := cryptobin_sm2.MarshalSM2PrivateKey(this.privateKey)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成加密数据
    privateBlock, err := crypto_x509.EncryptPEMBlock(
        rand.Reader,
        "SM2 PRIVATE KEY",
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

// ====================

// 生成私钥 pem 数据
func (this SM2) CreatePKCS8PrivateKey() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePrivateKeyToPem(this.privateKey, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = keyData

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// eg:
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this SM2) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    opt, err := cryptobin_pkcs8s.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := x509.MarshalSm2UnecryptedPrivateKey(this.privateKey)
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

// 生成私钥带密码 pem 数据，sm2 库自带
func (this SM2) CreateSM2PrivateKeyWithPassword(password string) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePrivateKeyToPem(this.privateKey, []byte(password))
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = keyData

    return this
}

// ====================

// 生成公钥 pem 数据
func (this SM2) CreatePublicKey() SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: publicKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePublicKeyToPem(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = keyData

    return this
}
