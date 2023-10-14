package curve25519

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/dh/curve25519"
)

// 生成密钥
func (this Curve25519) GenerateKey() Curve25519 {
    privateKey, publicKey, err := curve25519.GenerateKey(rand.Reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}

// 生成密钥
func GenerateKey() Curve25519 {
    return defaultCurve25519.GenerateKey()
}

// 生成密钥
func (this Curve25519) GenerateKeyWithSeed(reader io.Reader) Curve25519 {
    privateKey, publicKey, err := curve25519.GenerateKey(reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}

// 生成密钥
func GenerateKeyWithSeed(reader io.Reader) Curve25519 {
    return defaultCurve25519.GenerateKeyWithSeed(reader)
}

// ==========

// 私钥
func (this Curve25519) FromPrivateKey(key []byte) Curve25519 {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*curve25519.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) Curve25519 {
    return defaultCurve25519.FromPrivateKey(key)
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

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Curve25519 {
    return defaultCurve25519.FromPrivateKeyWithPassword(key, password)
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

// 公钥
func FromPublicKey(key []byte) Curve25519 {
    return defaultCurve25519.FromPublicKey(key)
}

// ==========

// 根据私钥 x, y 生成
func (this Curve25519) FromKeyXYHexString(xString string, yString string) Curve25519 {
    encoding := tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)
    y, _ := encoding.HexDecode(yString)

    priv := &curve25519.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 根据私钥 x, y 生成
func FromKeyXYHexString(xString string, yString string) Curve25519 {
    return defaultCurve25519.FromKeyXYHexString(xString, yString)
}

// 根据私钥 x 生成
func (this Curve25519) FromPrivateKeyXHexString(xString string) Curve25519 {
    encoding := tool.NewEncoding()

    x, _ := encoding.HexDecode(xString)

    priv := &curve25519.PrivateKey{}
    priv.X = x

    public, _ := curve25519.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据私钥 x 生成
func FromPrivateKeyXHexString(xString string) Curve25519 {
    return defaultCurve25519.FromPrivateKeyXHexString(xString)
}

// 根据公钥 y 生成
func (this Curve25519) FromPublicKeyYHexString(yString string) Curve25519 {
    encoding := tool.NewEncoding()

    y, _ := encoding.HexDecode(yString)

    public := &curve25519.PublicKey{}
    public.Y = y

    this.publicKey = public

    return this
}

// 根据公钥 y 生成
func FromPublicKeyYHexString(yString string) Curve25519 {
    return defaultCurve25519.FromPublicKeyYHexString(yString)
}

// ==========

// DER 私钥
func (this Curve25519) FromPrivateKeyDer(der []byte) Curve25519 {
    key := tool.EncodeDerToPem(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*curve25519.PrivateKey)

    return this
}

// DER 公钥
func (this Curve25519) FromPublicKeyDer(der []byte) Curve25519 {
    key := tool.EncodeDerToPem(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*curve25519.PublicKey)

    return this
}
