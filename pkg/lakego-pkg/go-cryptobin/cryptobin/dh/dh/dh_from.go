package dh

import (
    "crypto/rand"

    "github.com/deatil/go-cryptobin/dhd/dh"
)

// 私钥
func (this Dh) FromPrivateKey(key []byte) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥带密码
func (this Dh) FromPrivateKeyWithPassword(key []byte, password string) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 公钥
func (this Dh) FromPublicKey(key []byte) Dh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}

// 生成密钥
func (this Dh) GenerateKey(typ string) Dh {
    var param dh.Parameters

    switch typ {
        case "P512":
            param = dh.P512()
        case "P1024":
            param = dh.P1024()
        case "P2048_2":
            param = dh.P2048_2()
        case "P2048":
            param = dh.P2048()
        case "P3072":
            param = dh.P3072()
        case "P4096":
            param = dh.P4096()
        default:
            param = dh.P2048()
    }

    this.privateKey, this.publicKey, this.Error = dh.GenerateKey(param, rand.Reader)

    return this
}
