package curve25519

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/dhd/curve25519"
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
// obj := New().GenerateKey("P2048")
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this Curve25519) CreatePrivateKey() Curve25519 {
    if this.privateKey == nil {
        this.Error = errors.New("Curve25519: [CreatePrivateKey()] privateKey error.")
        return this
    }

    privateKey, err := curve25519.MarshalPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: privateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this Curve25519) CreatePrivateKeyWithPassword(password string, opts ...any) Curve25519 {
    if len(opts) > 0 {
        switch optString := opts[0].(type) {
            case string:
                isPkcs8Pbe := cryptobin_pkcs8pbe.CheckCipherFromName(optString)

                if isPkcs8Pbe {
                    return this.CreatePbePrivateKeyWithPassword(password, optString)
                }
        }
    }

    return this.CreateKdfPrivateKeyWithPassword(password, opts...)
}

// 生成私钥带密码 pem 数据
// CreateKdfPrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this Curve25519) CreateKdfPrivateKeyWithPassword(password string, opts ...any) Curve25519 {
    if this.privateKey == nil {
        this.Error = errors.New("Curve25519: [CreateKdfPrivateKeyWithPassword()] privateKey error.")
        return this
    }

    opt, err := cryptobin_pkcs8.ParseOpts(opts...)
    if err != nil {
        this.Error = err
        return this
    }

    // 生成私钥
    privateKey, err := curve25519.MarshalPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs8.EncryptPKCS8PrivateKey(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKey,
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

// 生成 PKCS8 私钥带密码 pem 数据
func (this Curve25519) CreatePbePrivateKeyWithPassword(password string, alg string) Curve25519 {
    if this.privateKey == nil {
        this.Error = errors.New("Curve25519: [CreatePbePrivateKeyWithPassword()] privateKey error.")
        return this
    }

    // 生成私钥
    privateKey, err := curve25519.MarshalPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    pemCipher := cryptobin_pkcs8pbe.GetCipherFromName(alg)

    // 生成加密数据
    privateBlock, err := cryptobin_pkcs8pbe.EncryptPKCS8PrivateKey(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        privateKey,
        []byte(password),
        pemCipher,
    )
    if err != nil {
        this.Error = err
        return this
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 生成公钥 pem 数据
func (this Curve25519) CreatePublicKey() Curve25519 {
    var publicKey *curve25519.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("Curve25519: [CreatePublicKey()] privateKey error.")

            return this
        }

        publicKey = &this.privateKey.PublicKey
    } else {
        publicKey = this.publicKey
    }

    publicKeyBytes, err := curve25519.MarshalPublicKey(publicKey)
    if err != nil {
        this.Error = err
        return this
    }

    publicBlock := &pem.Block{
        Type: "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(publicBlock)

    return this
}

// 根据公钥和私钥生成密钥
func (this Curve25519) CreateSecret() Curve25519 {
    if this.privateKey == nil {
        this.Error = errors.New("Curve25519: [CreateSecret()] privateKey error.")
        return this
    }

    if this.publicKey == nil {
        this.Error = errors.New("Curve25519: [CreateSecret()] publicKey error.")
        return this
    }

    this.secretData = curve25519.ComputeSecret(this.privateKey, this.publicKey)

    return this
}
