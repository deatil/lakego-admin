package curve25519

import (
    "crypto/rand"

    "github.com/deatil/go-cryptobin/dh/curve25519"
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this Curve25519) FromPrivateKey(key []byte) Curve25519 {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*curve25519.PrivateKey)

    return this
}

// 私钥带密码
func (this Curve25519) FromPrivateKeyWithPassword(key []byte, password string) Curve25519 {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*curve25519.PrivateKey)

    return this
}

// 公钥
func (this Curve25519) FromPublicKey(key []byte) Curve25519 {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*curve25519.PublicKey)

    return this
}

// 根据私钥 x, y 生成
func (this Curve25519) FromKeyXYHexString(xString string, yString string) Curve25519 {
    encoding := cryptobin_tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)
    y, _ := encoding.HexDecode(yString)

    priv := &curve25519.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 根据私钥 x 生成
func (this Curve25519) FromPrivateKeyXHexString(xString string) Curve25519 {
    encoding := cryptobin_tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)

    priv := &curve25519.PrivateKey{}
    priv.X = x

    public, _ := curve25519.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据公钥 y 生成
func (this Curve25519) FromPublicKeyYHexString(yString string) Curve25519 {
    encoding := cryptobin_tool.NewEncoding()

    y, _ := encoding.HexDecode(yString)

    public := &curve25519.PublicKey{}
    public.Y = y

    this.publicKey = public

    return this
}

// 生成密钥
func (this Curve25519) GenerateKey() Curve25519 {
    privateKey, publicKey, err := curve25519.GenerateKey(rand.Reader)
    
    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}
