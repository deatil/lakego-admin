package ecdh

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/dh/ecdh"
)

// 生成密钥
func (this ECDH) GenerateKeyWithSeed(reader io.Reader) ECDH {
    privateKey, publicKey, err := ecdh.GenerateKey(this.curve, reader)

    this.privateKey = privateKey
    this.publicKey  = publicKey

    return this.AppendError(err)
}

// 生成密钥
// 可用参数 [P521 | P384 | P256 | P224]
func GenerateKeyWithSeed(reader io.Reader, curve string) ECDH {
    return defaultECDH.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this ECDH) GenerateKey() ECDH {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
// 可用参数 [P521 | P384 | P256 | P224]
func GenerateKey(curve string) ECDH {
    return defaultECDH.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this ECDH) FromPrivateKey(key []byte) ECDH {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKey(key []byte) ECDH {
    return defaultECDH.FromPrivateKey(key)
}

// 私钥带密码
func (this ECDH) FromPrivateKeyWithPassword(key []byte, password string) ECDH {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) ECDH {
    return defaultECDH.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this ECDH) FromPublicKey(key []byte) ECDH {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 公钥
func FromPublicKey(key []byte) ECDH {
    return defaultECDH.FromPublicKey(key)
}

// ==========

// 根据私钥 x, y 生成
func (this ECDH) FromKeyXYString(xString string, yString string) ECDH {
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

// 根据私钥 x, y 生成
func FromKeyXYString(xString string, yString string) ECDH {
    return defaultECDH.FromKeyXYString(xString, yString)
}

// 根据私钥 x 生成
func (this ECDH) FromPrivateKeyXString(xString string) ECDH {
    x, _ := encoding.HexDecode(xString)

    priv := &ecdh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Curve = this.curve

    public, _ := ecdh.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据私钥 x 生成
func FromPrivateKeyXString(xString string) ECDH {
    return defaultECDH.FromPrivateKeyXString(xString)
}

// 根据公钥 y 生成
func (this ECDH) FromPublicKeyYString(yString string) ECDH {
    y, _ := encoding.HexDecode(yString)

    public := &ecdh.PublicKey{}
    public.Y = y
    public.Curve = this.curve

    this.publicKey = public

    return this
}

// 根据公钥 y 生成
func FromPublicKeyYString(yString string) ECDH {
    return defaultECDH.FromPublicKeyYString(yString)
}

// ==========

// DER 私钥
func (this ECDH) FromPrivateKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// DER 公钥
func (this ECDH) FromPublicKeyDer(der []byte) ECDH {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}
