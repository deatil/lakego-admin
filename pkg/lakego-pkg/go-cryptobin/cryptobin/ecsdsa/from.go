package ecsdsa

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/ecsdsa"
)

// 生成密钥
func (this ECSDSA) GenerateKeyWithSeed(reader io.Reader) ECSDSA {
    privateKey, err := ecsdsa.GenerateKey(reader, this.curve)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKeyWithSeed(reader io.Reader, curve string) ECSDSA {
    return defaultECSDSA.SetCurve(curve).GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this ECSDSA) GenerateKey() ECSDSA {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥
// 可选 [P521 | P384 | P256 | P224]
func GenerateKey(curve string) ECSDSA {
    return defaultECSDSA.SetCurve(curve).GenerateKey()
}

// ==========

// 私钥
func (this ECSDSA) FromPrivateKey(key []byte) ECSDSA {
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
func FromPrivateKey(key []byte) ECSDSA {
    return defaultECSDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this ECSDSA) FromPrivateKeyWithPassword(key []byte, password string) ECSDSA {
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
func FromPrivateKeyWithPassword(key []byte, password string) ECSDSA {
    return defaultECSDSA.FromPrivateKeyWithPassword(key, password)
}

// ==========

// 私钥
func (this ECSDSA) FromPKCS1PrivateKey(key []byte) ECSDSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥
func FromPKCS1PrivateKey(key []byte) ECSDSA {
    return defaultECSDSA.FromPKCS1PrivateKey(key)
}

// 私钥带密码
func (this ECSDSA) FromPKCS1PrivateKeyWithPassword(key []byte, password string) ECSDSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) ECSDSA {
    return defaultECSDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this ECSDSA) FromPKCS8PrivateKey(key []byte) ECSDSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) ECSDSA {
    return defaultECSDSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this ECSDSA) FromPKCS8PrivateKeyWithPassword(key []byte, password string) ECSDSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) ECSDSA {
    return defaultECSDSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥
func (this ECSDSA) FromPublicKey(key []byte) ECSDSA {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) ECSDSA {
    return defaultECSDSA.FromPublicKey(key)
}

// ==========

// DER 私钥
func (this ECSDSA) FromPKCS1PrivateKeyDer(der []byte) ECSDSA {
    key := pem.EncodeToPEM(der, "EC PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 私钥
func (this ECSDSA) FromPKCS8PrivateKeyDer(der []byte) ECSDSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this ECSDSA) FromPublicKeyDer(der []byte) ECSDSA {
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
func (this ECSDSA) FromPublicKeyXYString(xString string, yString string) ECSDSA {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &ecsdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥字符对，需要设置对应的 curve
func (this ECSDSA) FromPublicKeyXYBytes(xBytes, yBytes []byte) ECSDSA {
    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    this.publicKey = &ecsdsa.PublicKey{
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
func (this ECSDSA) FromPublicKeyUncompressString(key string) ECSDSA {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.Unmarshal(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("go-cryptobin/ecsdsa: publicKey uncompress string error")

        return this.AppendError(err)
    }

    this.publicKey = &ecsdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文压缩
// 需要设置对应的 curve
// public-key hex: 027c******** || 036c********
func (this ECSDSA) FromPublicKeyCompressString(key string) ECSDSA {
    k, _ := encoding.HexDecode(key)

    x, y := elliptic.UnmarshalCompressed(this.curve, k)
    if x == nil || y == nil {
        err := errors.New("go-cryptobin/ecsdsa: publicKey compress string error")

        return this.AppendError(err)
    }

    this.publicKey = &ecsdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文，需要设置对应的 curve
func (this ECSDSA) FromPublicKeyString(key string) ECSDSA {
    byteLen := (this.curve.Params().BitSize + 7) / 8

    k, _ := encoding.HexDecode(key)

    if len(k) == 1+byteLen {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文，需要设置对应的 curve
// private-key: 07e4********;
func (this ECSDSA) FromPrivateKeyString(keyString string) ECSDSA {
    k, _ := new(big.Int).SetString(keyString, 16)

    return this.FromPrivateKeyBytes(k.Bytes())
}

// ==========

// 公钥明文, hex 或者 base64 解码后
// 需要设置对应的 curve
func (this ECSDSA) FromPublicKeyBytes(pub []byte) ECSDSA {
    key := encoding.HexEncode(pub)

    return this.FromPublicKeyString(key)
}

// 明文私钥生成私钥结构体
// 需要设置对应的 curve
func (this ECSDSA) FromPrivateKeyBytes(priByte []byte) ECSDSA {
    priv, err := ecsdsa.NewPrivateKey(this.curve, priByte)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this ECSDSA) FromBytes(data []byte) ECSDSA {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) ECSDSA {
    return defaultECSDSA.FromBytes(data)
}

// 字符
func (this ECSDSA) FromString(data string) ECSDSA {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) ECSDSA {
    return defaultECSDSA.FromString(data)
}

// Base64
func (this ECSDSA) FromBase64String(data string) ECSDSA {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) ECSDSA {
    return defaultECSDSA.FromBase64String(data)
}

// Hex
func (this ECSDSA) FromHexString(data string) ECSDSA {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) ECSDSA {
    return defaultECSDSA.FromHexString(data)
}
