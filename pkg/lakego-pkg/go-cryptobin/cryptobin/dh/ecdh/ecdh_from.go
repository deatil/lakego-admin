package ecdh

import (
    "crypto/rand"

    "github.com/deatil/go-cryptobin/dh/ecdh"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this Ecdh) FromPrivateKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥带密码
func (this Ecdh) FromPrivateKeyWithPassword(key []byte, password string) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 公钥
func (this Ecdh) FromPublicKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 根据私钥 x, y 生成
func (this Ecdh) FromKeyXYHexString(xString string, yString string) Ecdh {
    encoding := cryptobin_tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)
    y, _ := encoding.HexDecode(yString)

    priv := &ecdh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y
    priv.PublicKey.Curve = this.curve

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 根据私钥 x 生成
func (this Ecdh) FromPrivateKeyXHexString(xString string) Ecdh {
    encoding := cryptobin_tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)

    priv := &ecdh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Curve = this.curve

    public, _ := ecdh.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据公钥 y 生成
func (this Ecdh) FromPublicKeyYHexString(yString string) Ecdh {
    encoding := cryptobin_tool.NewEncoding()

    y, _ := encoding.HexDecode(yString)

    public := &ecdh.PublicKey{}
    public.Y = y
    public.Curve = this.curve

    this.publicKey = public

    return this
}

// 生成密钥
func (this Ecdh) GenerateKey() Ecdh {
    privateKey, publicKey, err := ecdh.GenerateKey(this.curve, rand.Reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}
