package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// Cipher 列表
var CipherMap = map[string]pkcs8.CipherBlock{
    "DESCBC":     pkcs8.DESCBC,
    "DESEDE3CBC": pkcs8.DESEDE3CBC,
    "AES128CBC":  pkcs8.AES128CBC,
    "AES192CBC":  pkcs8.AES192CBC,
    "AES256CBC":  pkcs8.AES256CBC,
}

type (
    // 配置
    Opts = pkcs8.Opts
    // PBKDF2 配置
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = pkcs8.ScryptOpts
)

// 解析配置
func parseOpt(opts ...any) (pkcs8.Opts, error) {
    if len(opts) == 0 {
        return pkcs8.DefaultOpts, nil
    }

    switch newOpt := opts[0].(type) {
        case pkcs8.Opts:
            return newOpt, nil
        case string:
            // DESCBC | DESEDE3CBC | AES128CBC
            // AES192CBC | AES256CBC
            opt := "AES256CBC"
            if len(opts) > 0 {
                opt = opts[0].(string)
            }

            // MD5 | SHA1 | SHA224 | SHA256 | SHA384
            // SHA512 | SHA512_224 | SHA512_256
            encryptHash := "SHA256"
            if len(opts) > 1 {
                encryptHash = opts[1].(string)
            }

            // 具体方式
            cipher, ok := CipherMap[opt]
            if !ok {
                return pkcs8.Opts{}, errors.New("PEMCipher not exists.")
            }

            hmacHash := cryptobin_tool.NewHash().
                GetCryptoHash(encryptHash)

            // 设置
            enOpt := pkcs8.Opts{
                Cipher:  cipher,
                KDFOpts: pkcs8.PBKDF2Opts{
                    SaltSize:       16,
                    IterationCount: 10000,
                    HMACHash:       hmacHash,
                },
            }

            return enOpt, nil
        default:
            return pkcs8.DefaultOpts, nil
    }
}

// 私钥, PKCS1 别名
func (this Rsa) CreatePrivateKey() Rsa {
    return this.CreatePKCS1PrivateKey()
}

// 私钥带密码, PKCS1 别名
func (this Rsa) CreatePrivateKeyWithPassword(password string, opts ...string) Rsa {
    return this.CreatePKCS1PrivateKeyWithPassword(password, opts...)
}

// PKCS1 私钥
func (this Rsa) CreatePKCS1PrivateKey() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
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

// PKCS1 私钥带密码
// CreatePKCS1PrivateKeyWithPassword("123", "AES256CBC")
func (this Rsa) CreatePKCS1PrivateKeyWithPassword(password string, opts ...string) Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
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
        this.Error = errors.New("PEMCipher not exists.")
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

// PKCS8 私钥
func (this Rsa) CreatePKCS8PrivateKey() Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
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

// PKCS8 私钥带密码
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this Rsa) CreatePKCS8PrivateKeyWithPassword(password string, opts ...any) Rsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    opt, err := parseOpt(opts...)
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
    privateBlock, err := pkcs8.EncryptPKCS8PrivateKey(
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

// 公钥
func (this Rsa) CreatePublicKey() Rsa {
    var publicKey *rsa.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

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
