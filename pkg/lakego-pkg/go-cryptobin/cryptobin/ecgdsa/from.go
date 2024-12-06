package ecgdsa

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ecgdsa"
)

// 生成密钥
func (this ECGDSA) GenerateKeyWithSeed(reader io.Reader) ECGDSA {
    privateKey, err := ecgdsa.GenerateKey(reader, this.curve)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKeyWithSeed(reader io.Reader, curve string) ECGDSA {
    return defaultECGDSA.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this ECGDSA) GenerateKey() ECGDSA {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKey(curve string) ECGDSA {
    return defaultECGDSA.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this ECGDSA) FromPrivateKey(key []byte) ECGDSA {
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
func FromPrivateKey(key []byte) ECGDSA {
    return defaultECGDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this ECGDSA) FromPrivateKeyWithPassword(key []byte, password string) ECGDSA {
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
func FromPrivateKeyWithPassword(key []byte, password string) ECGDSA {
    return defaultECGDSA.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this ECGDSA) FromPKCS1PrivateKey(key []byte) ECGDSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) ECGDSA {
    return defaultECGDSA.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this ECGDSA) FromPKCS1PrivateKeyWithPassword(key []byte, password string) ECGDSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) ECGDSA {
    return defaultECGDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this ECGDSA) FromPKCS8PrivateKey(key []byte) ECGDSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) ECGDSA {
    return defaultECGDSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this ECGDSA) FromPKCS8PrivateKeyWithPassword(key []byte, password string) ECGDSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) ECGDSA {
    return defaultECGDSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this ECGDSA) FromPublicKey(key []byte) ECGDSA {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) ECGDSA {
    return defaultECGDSA.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this ECGDSA) FromPKCS1PrivateKeyDer(der []byte) ECGDSA {
    key := pem.EncodeToPEM(der, "EC PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this ECGDSA) FromPKCS8PrivateKeyDer(der []byte) ECGDSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this ECGDSA) FromPublicKeyDer(der []byte) ECGDSA {
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
func (this ECGDSA) FromPublicKeyXYString(xString string, yString string) ECGDSA {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &ecgdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥字符对，需要设置对应的 curve
func (this ECGDSA) FromPublicKeyXYBytes(xBytes, yBytes []byte) ECGDSA {
    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    this.publicKey = &ecgdsa.PublicKey{
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
func (this ECGDSA) FromPublicKeyUncompressString(key string) ECGDSA {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.Unmarshal(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey uncompress string error")

        return this.AppendError(err)
    }

    this.publicKey = &ecgdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文压缩
// 需要设置对应的 curve
// public-key hex: 027c******** || 036c********
func (this ECGDSA) FromPublicKeyCompressString(key string) ECGDSA {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.UnmarshalCompressed(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("publicKey compress string error")

        return this.AppendError(err)
    }

    this.publicKey = &ecgdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文，需要设置对应的 curve
func (this ECGDSA) FromPublicKeyString(key string) ECGDSA {
    byteLen := (this.curve.Params().BitSize + 7) / 8

    k, _ := encoding.HexDecode(key)

    if len(k) == 1+byteLen {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文，需要设置对应的 curve
// private-key: 07e4********;
func (this ECGDSA) FromPrivateKeyString(keyString string) ECGDSA {
    k, _ := new(big.Int).SetString(keyString, 16)

    return this.FromPrivateKeyBytes(k.Bytes())
}

// ==========

// 公钥明文, hex 或者 base64 解码后
// 需要设置对应的 curve
func (this ECGDSA) FromPublicKeyBytes(pub []byte) ECGDSA {
    key := encoding.HexEncode(pub)

    return this.FromPublicKeyString(key)
}

// 明文私钥生成私钥结构体
// 需要设置对应的 curve
func (this ECGDSA) FromPrivateKeyBytes(priByte []byte) ECGDSA {
    priv, err := ecgdsa.NewPrivateKey(this.curve, priByte)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this ECGDSA) FromBytes(data []byte) ECGDSA {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) ECGDSA {
    return defaultECGDSA.FromBytes(data)
}

// 字符
func (this ECGDSA) FromString(data string) ECGDSA {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) ECGDSA {
    return defaultECGDSA.FromString(data)
}

// Base64
func (this ECGDSA) FromBase64String(data string) ECGDSA {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) ECGDSA {
    return defaultECGDSA.FromBase64String(data)
}

// Hex
func (this ECGDSA) FromHexString(data string) ECGDSA {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) ECGDSA {
    return defaultECGDSA.FromHexString(data)
}
