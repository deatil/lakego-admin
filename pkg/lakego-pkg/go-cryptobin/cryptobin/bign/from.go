package bign

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/bign"
)

// 生成密钥
func (this Bign) GenerateKeyWithSeed(reader io.Reader) Bign {
    privateKey, err := bign.GenerateKey(reader, this.curve)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [Bign256v1 | Bign384v1 | Bign512v1]
func GenerateKeyWithSeed(reader io.Reader, curve string) Bign {
    return defaultBign.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this Bign) GenerateKey() Bign {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
// 可选 [Bign256v1 | Bign384v1 | Bign512v1]
func GenerateKey(curve string) Bign {
    return defaultBign.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this Bign) FromPrivateKey(key []byte) Bign {
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
func FromPrivateKey(key []byte) Bign {
    return defaultBign.FromPrivateKey(key)
}

// 私钥带密码
func (this Bign) FromPrivateKeyWithPassword(key []byte, password string) Bign {
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
func FromPrivateKeyWithPassword(key []byte, password string) Bign {
    return defaultBign.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this Bign) FromPKCS1PrivateKey(key []byte) Bign {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) Bign {
    return defaultBign.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this Bign) FromPKCS1PrivateKeyWithPassword(key []byte, password string) Bign {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) Bign {
    return defaultBign.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this Bign) FromPKCS8PrivateKey(key []byte) Bign {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Bign {
    return defaultBign.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this Bign) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Bign {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Bign {
    return defaultBign.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this Bign) FromPublicKey(key []byte) Bign {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) Bign {
    return defaultBign.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this Bign) FromPKCS1PrivateKeyDer(der []byte) Bign {
    key := pem.EncodeToPEM(der, "Bign PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this Bign) FromPKCS8PrivateKeyDer(der []byte) Bign {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this Bign) FromPublicKeyDer(der []byte) Bign {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

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
func (this Bign) FromPublicKeyXYString(xString string, yString string) Bign {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &bign.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥字符对，需要设置对应的 curve
func (this Bign) FromPublicKeyXYBytes(xBytes, yBytes []byte) Bign {
    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    this.publicKey = &bign.PublicKey{
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
func (this Bign) FromPublicKeyUncompressString(key string) Bign {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.Unmarshal(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey uncompress string error")

        return this.AppendError(err)
    }

    this.publicKey = &bign.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文压缩
// 需要设置对应的 curve
// public-key hex: 027c******** || 036c********
func (this Bign) FromPublicKeyCompressString(key string) Bign {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.UnmarshalCompressed(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey compress string error")

        return this.AppendError(err)
    }

    this.publicKey = &bign.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文，需要设置对应的 curve
func (this Bign) FromPublicKeyString(key string) Bign {
    byteLen := (this.curve.Params().BitSize + 7) / 8

    k, _ := encoding.HexDecode(key)

    if len(k) == 1+byteLen {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文，需要设置对应的 curve
// private-key: 07e4********;
func (this Bign) FromPrivateKeyString(keyString string) Bign {
    k, _ := new(big.Int).SetString(keyString, 16)

    return this.FromPrivateKeyBytes(k.Bytes())
}

// ==========

// 公钥明文, hex 或者 base64 解码后
// 需要设置对应的 curve
func (this Bign) FromPublicKeyBytes(pub []byte) Bign {
    key := encoding.HexEncode(pub)

    return this.FromPublicKeyString(key)
}

// 明文私钥生成私钥结构体
// 需要设置对应的 curve
func (this Bign) FromPrivateKeyBytes(priByte []byte) Bign {
    priv, err := bign.NewPrivateKey(this.curve, priByte)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this Bign) FromBytes(data []byte) Bign {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Bign {
    return defaultBign.FromBytes(data)
}

// 字符
func (this Bign) FromString(data string) Bign {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Bign {
    return defaultBign.FromString(data)
}

// Base64
func (this Bign) FromBase64String(data string) Bign {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) Bign {
    return defaultBign.FromBase64String(data)
}

// Hex
func (this Bign) FromHexString(data string) Bign {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) Bign {
    return defaultBign.FromHexString(data)
}
