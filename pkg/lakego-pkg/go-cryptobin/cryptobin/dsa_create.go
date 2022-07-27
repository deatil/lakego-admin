package cryptobin

import (
    "errors"
    "crypto/dsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
)

// 私钥
func (this DSA) CreatePrivateKey() DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    privateKeyBytes, err := this.MarshalPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
    }

    privateBlock := &pem.Block{
        Type: "DSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 私钥带密码
// CreatePrivateKeyWithPassword("123", "AES256CBC")
func (this DSA) CreatePrivateKeyWithPassword(password string, opts ...string) DSA {
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
    x509PrivateKey, err := this.MarshalPrivateKey(this.privateKey)
    if err != nil {
        this.Error = err
        return this
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
        this.Error = err
        return this
    }

    this.keyData = pem.EncodeToMemory(privateBlock)

    return this
}

// 公钥
func (this DSA) CreatePublicKey() DSA {
    var publicKey *dsa.PublicKey

    if this.publicKey == nil {
        if this.privateKey == nil {
            this.Error = errors.New("privateKey error.")

            return this
        }

        publicKey = &this.privateKey.PublicKey
    } else {
        publicKey = this.publicKey
    }

    publicKeyBytes, err := this.MarshalPublicKey(publicKey)
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
