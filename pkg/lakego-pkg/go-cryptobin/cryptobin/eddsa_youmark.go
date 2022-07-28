package cryptobin

import (
    "errors"
    "crypto/ed25519"
    "encoding/pem"
)

// 设置私钥带密码
func EdDSAFromYoumarkPKCS8PrivateKeyWithPassword(key []byte, password string) EdDSA {
    return NewEdDSA().FromYoumarkPKCS8PrivateKeyWithPassword(key, password)
}

// 设置私钥带密码
func (this EdDSA) FromYoumarkPKCS8PrivateKeyWithPassword(key []byte, password string) EdDSA {
    var err error

    // 解析 PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        this.Error = errors.New("invalid key: Key must be a PEM encoded PKCS8 key")

        return this
    }

    var parsedKey any
    if parsedKey, _, err = YoumarkPKCS8ParsePrivateKey(block.Bytes, []byte(password)); err != nil {
        this.Error = err

        return this
    }

    var pkey ed25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
        this.Error = errors.New("key is not a valid EdDSA private key")

        return this
    }

    this.privateKey = pkey

    return this
}

// 创建私钥带密码
func (this EdDSA) CreateYoumarkPKCS8PrivateKeyWithPassword(password string, opt ...YoumarkPKCS8Opts) EdDSA {
    var opts YoumarkPKCS8Opts

    if len(opt) > 0 {
        opts = opt[0]
    } else {
        opts = Youmark_PKCS8_AES256CBC_SHA256
    }

    der, err := YoumarkPKCS8MarshalPrivateKey(this.privateKey, []byte(password), &opts)
    if err != nil {
        this.Error = err

        return this
    }

    block := &pem.Block{
        Type: "ENCRYPTED PRIVATE KEY",
        Bytes: der,
    }

    this.keyData = pem.EncodeToMemory(block)

    return this
}
