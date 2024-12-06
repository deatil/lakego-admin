package dh

import (
    "io"
    "math/big"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/pubkey/dh/dh"
)

// 生成密钥
func (this DH) GenerateKeyWithSeed(reader io.Reader) DH {
    privateKey, publicKey, err := dh.GenerateKeyWithGroup(this.group, reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader, name string) DH {
    return defaultDH.SetGroup(name).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this DH) GenerateKey() DH {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
func GenerateKey(name string) DH {
    return defaultDH.SetGroup(name).GenerateKey()
}

// ==========

// 私钥
func (this DH) FromPrivateKey(key []byte) DH {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) DH {
    return defaultDH.FromPrivateKey(key)
}

// 私钥带密码
func (this DH) FromPrivateKeyWithPassword(key []byte, password string) DH {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) DH {
    return defaultDH.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this DH) FromPublicKey(key []byte) DH {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) DH {
    return defaultDH.FromPublicKey(key)
}

// ==========

// 根据密钥 x, y 生成
func (this DH) FromKeyXYString(xString string, yString string) DH {
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
func FromKeyXYString(xString string, yString string) DH {
    return defaultDH.FromKeyXYString(xString, yString)
}

// 根据私钥 x 生成
func (this DH) FromPrivateKeyXString(xString string) DH {
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
func FromPrivateKeyXString(xString string) DH {
    return defaultDH.FromPrivateKeyXString(xString)
}

// 根据公钥 y 生成
func (this DH) FromPublicKeyYString(yString string) DH {
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
func FromPublicKeyYString(yString string) DH {
    return defaultDH.FromPublicKeyYString(yString)
}

// ==========

// DER 私钥
func (this DH) FromPrivateKeyDer(der []byte) DH {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// DER 公钥
func (this DH) FromPublicKeyDer(der []byte) DH {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}
