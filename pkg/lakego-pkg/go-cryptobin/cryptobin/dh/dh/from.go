package dh

import (
    "io"
    "math/big"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/dh/dh"
)

// 私钥
func (this Dh) FromPrivateKey(key []byte) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) Dh {
    return defaultDH.FromPrivateKey(key)
}

// 私钥带密码
func (this Dh) FromPrivateKeyWithPassword(key []byte, password string) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Dh {
    return defaultDH.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this Dh) FromPublicKey(key []byte) Dh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) Dh {
    return defaultDH.FromPublicKey(key)
}

// ==========

// 根据密钥 x, y 生成
func (this Dh) FromKeyXYHexString(xString string, yString string) Dh {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    group := this.group

    parameters := dh.Parameters{
        P: group.P,
        G: group.G,
    }

    priv := &dh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y
    priv.PublicKey.Parameters = parameters

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 根据私钥 x, y 生成
func FromKeyXYHexString(xString string, yString string) Dh {
    return defaultDH.FromKeyXYHexString(xString, yString)
}

// 根据私钥 x 生成
func (this Dh) FromPrivateKeyXHexString(xString string) Dh {
    x, _ := new(big.Int).SetString(xString[:], 16)

    group := this.group

    parameters := dh.Parameters{
        P: group.P,
        G: group.G,
    }

    priv := &dh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Parameters = parameters

    public, _ := dh.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据私钥 x 生成
func FromPrivateKeyXHexString(xString string) Dh {
    return defaultDH.FromPrivateKeyXHexString(xString)
}

// 根据公钥 y 生成
func (this Dh) FromPublicKeyYHexString(yString string) Dh {
    y, _ := new(big.Int).SetString(yString[:], 16)

    group := this.group

    parameters := dh.Parameters{
        P: group.P,
        G: group.G,
    }

    public := &dh.PublicKey{}
    public.Y = y
    public.Parameters = parameters

    this.publicKey = public

    return this
}

// 根据公钥 y 生成
func FromPublicKeyYHexString(yString string) Dh {
    return defaultDH.FromPublicKeyYHexString(yString)
}

// ==========

// DER 私钥
func (this Dh) FromPrivateKeyDer(der []byte) Dh {
    key := tool.EncodeDerToPem(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// DER 公钥
func (this Dh) FromPublicKeyDer(der []byte) Dh {
    key := tool.EncodeDerToPem(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}

// ==========

// 生成密钥
func (this Dh) GenerateKey() Dh {
    privateKey, publicKey, err := dh.GenerateKeyWithGroup(this.group, rand.Reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}

// 生成密钥
func GenerateKey(name string) Dh {
    return defaultDH.SetGroup(name).GenerateKey()
}

// 生成密钥
func (this Dh) GenerateKeyWithSeed(reader io.Reader) Dh {
    privateKey, publicKey, err := dh.GenerateKeyWithGroup(this.group, reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader, name string) Dh {
    return defaultDH.SetGroup(name).GenerateKeyWithSeed(reader)
}
