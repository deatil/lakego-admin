package ecdh

import (
    "crypto/rand"

    "github.com/deatil/go-cryptobin/dhd/ecdh"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this Ecdh) FromPrivateKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥带密码
func (this Ecdh) FromPrivateKeyWithPassword(key []byte, password string) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 公钥
func (this Ecdh) FromPublicKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 根据私钥 x, y 生成
func (this Ecdh) FromKeyXYHexString(curve string, xString string, yString string) Ecdh {
    c := GetCurveFromName(curve)

    encoding := cryptobin_tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)
    y, _ := encoding.HexDecode(yString)

    priv := &ecdh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y
    priv.PublicKey.Curve = c

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 根据私钥 x 生成
func (this Ecdh) FromPrivateKeyXHexString(curve string, xString string) Ecdh {
    c := GetCurveFromName(curve)

    encoding := cryptobin_tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)

    priv := &ecdh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Curve = c

    public, _ := ecdh.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据公钥 y 生成
func (this Ecdh) FromPublicKeyYHexString(curve string, yString string) Ecdh {
    c := GetCurveFromName(curve)

    encoding := cryptobin_tool.NewEncoding()

    y, _ := encoding.HexDecode(yString)

    public := &ecdh.PublicKey{}
    public.Y = y
    public.Curve = c

    this.publicKey = public

    return this
}

// 生成密钥
// 可用参数 [P521 | P384 | P256 | P224]
func (this Ecdh) GenerateKey(curve string) Ecdh {
    c := GetCurveFromName(curve)

    this.privateKey, this.publicKey, this.Error = ecdh.GenerateKey(c, rand.Reader)

    return this
}

// 获取 Curve
func GetCurveFromName(name string) ecdh.Curve {
    var curve ecdh.Curve

    switch name {
        case "P521":
            curve = ecdh.P521()
        case "P384":
            curve = ecdh.P384()
        case "P256":
            curve = ecdh.P256()
        case "P224":
            curve = ecdh.P224()
        default:
            curve = ecdh.P224()
    }

    return curve
}
