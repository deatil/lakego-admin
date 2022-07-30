package ecdsa

import (
    "errors"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/pem"
    
    "github.com/deatil/go-cryptobin/pkcs8"
)

// 私钥
func (this Ecdsa) CreatePrivateKey() Ecdsa {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")

        return this
    }

    x509PrivateKey, err := x509.MarshalECPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "EC PRIVATE KEY",
        Bytes: x509PrivateKey,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 私钥带密码
// CreatePrivateKeyWithPassword("123", "AES256CBC")
func (this Ecdsa) CreatePrivateKeyWithPassword(password string, opts ...string) Ecdsa {
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
    x509PrivateKey, err := x509.MarshalECPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    // 生成加密数据
    privateBlock, err := x509.EncryptPEMBlock(
        rand.Reader,
        "EC PRIVATE KEY",
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
func (this Ecdsa) CreatePKCS8PrivateKey() Ecdsa {
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

// PKCS8 私钥带密码
// CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256")
func (this Ecdsa) CreatePKCS8PrivateKeyWithPassword(password string, opts ...string) Ecdsa {
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
    privateBlock, err := pkcs8.EncryptPKCS8PrivateKey(
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
func (this Ecdsa) CreatePublicKey() Ecdsa {
    var publicKey *ecdsa.PublicKey

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
