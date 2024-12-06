package ecdsa

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 生成密钥
func (this ECDSA) GenerateKeyWithSeed(reader io.Reader) ECDSA {
    privateKey, err := ecdsa.GenerateKey(this.curve, reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKeyWithSeed(reader io.Reader, curve string) ECDSA {
    return defaultECDSA.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this ECDSA) GenerateKey() ECDSA {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKey(curve string) ECDSA {
    return defaultECDSA.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this ECDSA) FromPrivateKey(key []byte) ECDSA {
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
func FromPrivateKey(key []byte) ECDSA {
    return defaultECDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this ECDSA) FromPrivateKeyWithPassword(key []byte, password string) ECDSA {
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
func FromPrivateKeyWithPassword(key []byte, password string) ECDSA {
    return defaultECDSA.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this ECDSA) FromPKCS1PrivateKey(key []byte) ECDSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) ECDSA {
    return defaultECDSA.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this ECDSA) FromPKCS1PrivateKeyWithPassword(key []byte, password string) ECDSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) ECDSA {
    return defaultECDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this ECDSA) FromPKCS8PrivateKey(key []byte) ECDSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) ECDSA {
    return defaultECDSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this ECDSA) FromPKCS8PrivateKeyWithPassword(key []byte, password string) ECDSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) ECDSA {
    return defaultECDSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this ECDSA) FromPublicKey(key []byte) ECDSA {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) ECDSA {
    return defaultECDSA.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this ECDSA) FromPKCS1PrivateKeyDer(der []byte) ECDSA {
    key := pem.EncodeToPEM(der, "EC PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this ECDSA) FromPKCS8PrivateKeyDer(der []byte) ECDSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this ECDSA) FromPublicKeyDer(der []byte) ECDSA {
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
func (this ECDSA) FromPublicKeyXYString(xString string, yString string) ECDSA {
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
func (this ECDSA) FromPublicKeyXYBytes(xBytes, yBytes []byte) ECDSA {
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
func (this ECDSA) FromPublicKeyUncompressString(key string) ECDSA {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.Unmarshal(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey uncompress string error")

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
func (this ECDSA) FromPublicKeyCompressString(key string) ECDSA {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.UnmarshalCompressed(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey compress string error")

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
func (this ECDSA) FromPublicKeyString(key string) ECDSA {
    byteLen := (this.curve.Params().BitSize + 7) / 8

    k, _ := encoding.HexDecode(key)

    if len(k) == 1+byteLen {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文，需要设置对应的 curve
// private-key: 07e4********;
func (this ECDSA) FromPrivateKeyString(keyString string) ECDSA {
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
func (this ECDSA) FromPublicKeyBytes(pub []byte) ECDSA {
    key := encoding.HexEncode(pub)

    return this.FromPublicKeyString(key)
}

// 明文私钥生成私钥结构体
// 需要设置对应的 curve
func (this ECDSA) FromPrivateKeyBytes(priByte []byte) ECDSA {
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
func (this ECDSA) FromBytes(data []byte) ECDSA {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) ECDSA {
    return defaultECDSA.FromBytes(data)
}

// 字符
func (this ECDSA) FromString(data string) ECDSA {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) ECDSA {
    return defaultECDSA.FromString(data)
}

// Base64
func (this ECDSA) FromBase64String(data string) ECDSA {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) ECDSA {
    return defaultECDSA.FromBase64String(data)
}

// Hex
func (this ECDSA) FromHexString(data string) ECDSA {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) ECDSA {
    return defaultECDSA.FromHexString(data)
}
