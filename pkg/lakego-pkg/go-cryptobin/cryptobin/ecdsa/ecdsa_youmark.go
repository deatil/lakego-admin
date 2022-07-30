package ecdsa

import (
    "errors"
    "crypto/ecdsa"
    "encoding/pem"
    
    "github.com/deatil/go-cryptobin/cryptobin/tool"
)

// 设置私钥带密码
func EcdsaFromYoumarkPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return NewEcdsa().FromYoumarkPKCS8PrivateKeyWithPassword(key, password)
}

// 设置私钥带密码
func (this Ecdsa) FromYoumarkPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    var err error

    // 解析 PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        this.Error = errors.New("invalid key: Key must be a PEM encoded PKCS8 key")

        return this
    }

    var parsedKey any
    if parsedKey, _, err = tool.YoumarkPKCS8ParsePrivateKey(block.Bytes, []byte(password)); err != nil {
        this.Error = err

        return this
    }

    var pkey *ecdsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
        this.Error = errors.New("key is not a valid Ecdsa private key")

        return this
    }

    this.privateKey = pkey

    return this
}

// 创建私钥带密码
func (this Ecdsa) CreateYoumarkPKCS8PrivateKeyWithPassword(password string, opt ...tool.YoumarkPKCS8Opts) Ecdsa {
    var opts tool.YoumarkPKCS8Opts

    if len(opt) > 0 {
        opts = opt[0]
    } else {
        opts = tool.Youmark_PKCS8_AES256CBC_SHA256
    }

    der, err := tool.YoumarkPKCS8MarshalPrivateKey(this.privateKey, []byte(password), &opts)
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
