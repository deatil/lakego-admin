package sm2

import (
    "errors"
    "crypto/rand"
    "encoding/pem"

    "github.com/tjfoc/gmsm/x509"

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
// obj := New().GenerateKey()
// priKey := obj.CreatePrivateKey().ToKeyString()
func (this SM2) CreatePrivateKey() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [CreatePrivateKey()] privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePrivateKeyToPem(this.privateKey, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = keyData

    return this
}

// 生成私钥带密码 pem 数据
func (this SM2) CreatePrivateKeyWithPassword(password string, opts ...any) SM2 {
    if len(opts) == 0 {
        return this.CreateSM2PrivateKeyWithPassword(password)
    }

    return this.CreatePKCS8PrivateKeyWithPassword(password, opts...)
}

// 生成私钥带密码 pem 数据
func (this SM2) CreateSM2PrivateKeyWithPassword(password string) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [CreatePrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePrivateKeyToPem(this.privateKey, []byte(password))
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = keyData

    return this
}

// 生成 PKCS8 私钥带密码 pem 数据
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this SM2) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) SM2 {
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
func (this SM2) CreatePKCS8KdfPrivateKeyWithPassword(password string, opts ...any) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [CreatePKCS8KdfPrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
    }

    opt, err := cryptobin_pkcs8.ParseOpts(opts...)
    if err != nil {
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := x509.MarshalSm2UnecryptedPrivateKey(this.privateKey)
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
func (this SM2) CreatePKCS8PbePrivateKeyWithPassword(password string, alg string) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [CreatePKCS8PbePrivateKeyWithPassword()] privateKey error.")
        return this.AppendError(err)
    }

    // 生成私钥
    x509PrivateKey, err := x509.MarshalSm2UnecryptedPrivateKey(this.privateKey)
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
func (this SM2) CreatePublicKey() SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: [CreatePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    keyData, err := x509.WritePublicKeyToPem(this.publicKey)
    if err != nil {
        return this.AppendError(err)
    }

    this.keyData = keyData

    return this
}
