package eddsa

import (
    "errors"
    "crypto/rand"
    "crypto/x509"
    "crypto/ed25519"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

type (
    // 配置
    Opts = pkcs8.Opts
    // PBKDF2 配置
    PBKDF2Opts = pkcs8.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = pkcs8.ScryptOpts
)

// Cipher 列表
var CipherMap = map[string]pkcs8.CipherBlock{
    "DESCBC":     pkcs8.DESCBC,
    "DESEDE3CBC": pkcs8.DESEDE3CBC,
    "AES128CBC":  pkcs8.AES128CBC,
    "AES192CBC":  pkcs8.AES192CBC,
    "AES256CBC":  pkcs8.AES256CBC,
}

// 私钥
func (this EdDSA) CreatePrivateKey() EdDSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 私钥带密码
// CreatePrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this EdDSA) CreatePrivateKeyWithPassword(password string, opts ...any) EdDSA {
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
func (this EdDSA) CreatePublicKey() EdDSA {
    var publicKey ed25519.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

            return this
        }

        publicKey = this.privateKey.Public().(ed25519.PublicKey)
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
            encryptHash := "SHA1"
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
