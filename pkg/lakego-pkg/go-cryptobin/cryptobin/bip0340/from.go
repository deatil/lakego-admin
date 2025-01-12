package bip0340

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/bip0340"
)

// 生成密钥
func (this BIP0340) GenerateKeyWithSeed(reader io.Reader) BIP0340 {
    privateKey, err := bip0340.GenerateKey(reader, this.curve)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224 | S256]
func GenerateKeyWithSeed(reader io.Reader, curve string) BIP0340 {
    return defaultBIP0340.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this BIP0340) GenerateKey() BIP0340 {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224 | S256]
func GenerateKey(curve string) BIP0340 {
    return defaultBIP0340.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this BIP0340) FromPrivateKey(key []byte) BIP0340 {
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
func FromPrivateKey(key []byte) BIP0340 {
    return defaultBIP0340.FromPrivateKey(key)
}

// 私钥带密码
func (this BIP0340) FromPrivateKeyWithPassword(key []byte, password string) BIP0340 {
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
func FromPrivateKeyWithPassword(key []byte, password string) BIP0340 {
    return defaultBIP0340.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this BIP0340) FromPKCS1PrivateKey(key []byte) BIP0340 {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) BIP0340 {
    return defaultBIP0340.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this BIP0340) FromPKCS1PrivateKeyWithPassword(key []byte, password string) BIP0340 {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) BIP0340 {
    return defaultBIP0340.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this BIP0340) FromPKCS8PrivateKey(key []byte) BIP0340 {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) BIP0340 {
    return defaultBIP0340.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this BIP0340) FromPKCS8PrivateKeyWithPassword(key []byte, password string) BIP0340 {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) BIP0340 {
    return defaultBIP0340.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this BIP0340) FromPublicKey(key []byte) BIP0340 {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) BIP0340 {
    return defaultBIP0340.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this BIP0340) FromPKCS1PrivateKeyDer(der []byte) BIP0340 {
    key := pem.EncodeToPEM(der, "EC PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this BIP0340) FromPKCS8PrivateKeyDer(der []byte) BIP0340 {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this BIP0340) FromPublicKeyDer(der []byte) BIP0340 {
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
func (this BIP0340) FromPublicKeyXYString(xString string, yString string) BIP0340 {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &bip0340.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥字符对，需要设置对应的 curve
func (this BIP0340) FromPublicKeyXYBytes(xBytes, yBytes []byte) BIP0340 {
    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    this.publicKey = &bip0340.PublicKey{
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
func (this BIP0340) FromPublicKeyUncompressString(key string) BIP0340 {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.Unmarshal(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey uncompress string error")

        return this.AppendError(err)
    }

    this.publicKey = &bip0340.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文压缩
// 需要设置对应的 curve
// public-key hex: 027c******** || 036c********
func (this BIP0340) FromPublicKeyCompressString(key string) BIP0340 {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.UnmarshalCompressed(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey compress string error")

        return this.AppendError(err)
    }

    this.publicKey = &bip0340.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文，需要设置对应的 curve
func (this BIP0340) FromPublicKeyString(key string) BIP0340 {
    byteLen := (this.curve.Params().BitSize + 7) / 8

    k, _ := encoding.HexDecode(key)

    if len(k) == 1+byteLen {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文，需要设置对应的 curve
// private-key: 07e4********;
func (this BIP0340) FromPrivateKeyString(keyString string) BIP0340 {
    k, _ := new(big.Int).SetString(keyString, 16)

    return this.FromPrivateKeyBytes(k.Bytes())
}

// ==========

// 公钥明文, hex 或者 base64 解码后
// 需要设置对应的 curve
func (this BIP0340) FromPublicKeyBytes(pub []byte) BIP0340 {
    key := encoding.HexEncode(pub)

    return this.FromPublicKeyString(key)
}

// 明文私钥生成私钥结构体
// 需要设置对应的 curve
func (this BIP0340) FromPrivateKeyBytes(priByte []byte) BIP0340 {
    priv, err := bip0340.NewPrivateKey(this.curve, priByte)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this BIP0340) FromBytes(data []byte) BIP0340 {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) BIP0340 {
    return defaultBIP0340.FromBytes(data)
}

// 字符
func (this BIP0340) FromString(data string) BIP0340 {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) BIP0340 {
    return defaultBIP0340.FromString(data)
}

// Base64
func (this BIP0340) FromBase64String(data string) BIP0340 {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) BIP0340 {
    return defaultBIP0340.FromBase64String(data)
}

// Hex
func (this BIP0340) FromHexString(data string) BIP0340 {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) BIP0340 {
    return defaultBIP0340.FromHexString(data)
}
