package cryptobin

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
)

// PKCS1 私钥
func (this Rsa) CreatePKCS1() Rsa {
    X509PrivateKey := x509.MarshalPKCS1PrivateKey(this.privateKey)

    privateBlock := &pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: X509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// PKCS1 私钥带密码
// CreatePKCS1WithPassword("123", "AES256CBC")
func (this Rsa) CreatePKCS1WithPassword(password string, opts ...string) Rsa {
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
func (this Rsa) CreatePKCS8() Rsa {
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
// CreatePKCS8WithPassword("123", "AES256CBC", "SHA256")
func (this Rsa) CreatePKCS8WithPassword(password string, opts ...string) Rsa {
    // DESCBC | DESEDE3CBC | AES128CBC
    // AES192CBC | AES256CBC
    opt := "AES256CBC"
    if len(opts) > 0 {
        opt = opts[0]
    }

    // MD5 | SHA1 | SHA224 | SHA256 | SHA384
    // SHA512 | SHA512_224 | SHA512_256
    encryptHash := "SHA1"
    if len(opts) > 1 {
        encryptHash = opts[1]
    }

    // 具体方式
    cipher, ok := PEMCiphers[opt]
    if !ok {
        this.Error = errors.New("PEMCipher not exists.")
        return this
    }

    // 生成私钥
    x509PrivateKey, err := x509.MarshalPKCS8PrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    // 生成加密数据
    privateBlock, err := EncryptPKCS8PrivateKey(
        rand.Reader,
        "ENCRYPTED PRIVATE KEY",
        x509PrivateKey,
        []byte(password),
        cipher,
        encryptHash,
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
