package ecdsa

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 生成密钥
func (this Ecdsa) GenerateKey() Ecdsa {
    privateKey, err := ecdsa.GenerateKey(this.curve, rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKey(curve string) Ecdsa {
    return defaultECDSA.SetCurve(curve).GenerateKey()
}

// 生成密钥
func (this Ecdsa) GenerateKeyWithSeed(reader io.Reader) Ecdsa {
    privateKey, err := ecdsa.GenerateKey(this.curve, reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKeyWithSeed(reader io.Reader, curve string) Ecdsa {
    return defaultECDSA.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// ==========

// 私钥
func (this Ecdsa) FromPrivateKey(key []byte) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err == nil {
        this.privateKey = privateKey

        return this
    }

    privateKey, err = this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPrivateKey(key []byte) Ecdsa {
    return defaultECDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this Ecdsa) FromPrivateKeyWithPassword(key []byte, password string) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err == nil {
        this.privateKey = privateKey

        return this
    }

    privateKey, err = this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return defaultECDSA.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this Ecdsa) FromPKCS1PrivateKey(key []byte) Ecdsa {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) Ecdsa {
    return defaultECDSA.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this Ecdsa) FromPKCS1PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return defaultECDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this Ecdsa) FromPKCS8PrivateKey(key []byte) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Ecdsa {
    return defaultECDSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this Ecdsa) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    return defaultECDSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this Ecdsa) FromPublicKey(key []byte) Ecdsa {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) Ecdsa {
    return defaultECDSA.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this Ecdsa) FromPKCS1PrivateKeyDer(der []byte) Ecdsa {
    key := cryptobin_tool.EncodeDerToPem(der, "EC PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this Ecdsa) FromPKCS8PrivateKeyDer(der []byte) Ecdsa {
    key := cryptobin_tool.EncodeDerToPem(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this Ecdsa) FromPublicKeyDer(der []byte) Ecdsa {
    key := cryptobin_tool.EncodeDerToPem(der, "PUBLIC KEY")

    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// ==========

// 公钥 x,y 16进制字符对
// 需要设置对应的 curve
// [xString: xHexString, yString: yHexString]
func (this Ecdsa) FromPublicKeyXYString(xString string, yString string) Ecdsa {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥字符对，需要设置对应的 curve
func (this Ecdsa) FromPublicKeyXYBytes(xBytes, yBytes []byte) Ecdsa {
    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// ==========

// 公钥明文未压缩
// 需要设置对应的 curve
// public-key hex: 047c********.
func (this Ecdsa) FromPublicKeyUncompressString(key string) Ecdsa {
    k, _ := cryptobin_tool.HexDecode(key)

    x, y := elliptic.Unmarshal(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("Ecdsa: publicKey uncompress string error")

        return this.AppendError(err)
    }

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文压缩
// 需要设置对应的 curve
// public-key hex: 027c******** || 036c********
func (this Ecdsa) FromPublicKeyCompressString(key string) Ecdsa {
    k, _ := cryptobin_tool.HexDecode(key)

    x, y := elliptic.UnmarshalCompressed(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("Ecdsa: publicKey compress string error")

        return this.AppendError(err)
    }

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文，需要设置对应的 curve
func (this Ecdsa) FromPublicKeyString(key string) Ecdsa {
    byteLen := (this.curve.Params().BitSize + 7) / 8

    k, _ := cryptobin_tool.HexDecode(key)

    if len(k) == 1+byteLen {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文，需要设置对应的 curve
// private-key: 07e4********;
func (this Ecdsa) FromPrivateKeyString(keyString string) Ecdsa {
    c := this.curve
    k, _ := new(big.Int).SetString(keyString[:], 16)

    priv := new(ecdsa.PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    this.privateKey = priv

    return this
}

// ==========

// 公钥明文, hex 或者 base64 解码后
// 需要设置对应的 curve
func (this Ecdsa) FromPublicKeyBytes(pub []byte) Ecdsa {
    key := cryptobin_tool.HexEncode(pub)

    return this.FromPublicKeyString(key)
}

// 明文私钥生成私钥结构体
// 需要设置对应的 curve
func (this Ecdsa) FromPrivateKeyBytes(priByte []byte) Ecdsa {
    c := this.curve
    k := new(big.Int).SetBytes(priByte)

    priv := new(ecdsa.PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this Ecdsa) FromBytes(data []byte) Ecdsa {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Ecdsa {
    return defaultECDSA.FromBytes(data)
}

// 字符
func (this Ecdsa) FromString(data string) Ecdsa {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Ecdsa {
    return defaultECDSA.FromString(data)
}

// Base64
func (this Ecdsa) FromBase64String(data string) Ecdsa {
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) Ecdsa {
    return defaultECDSA.FromBase64String(data)
}

// Hex
func (this Ecdsa) FromHexString(data string) Ecdsa {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) Ecdsa {
    return defaultECDSA.FromHexString(data)
}
