package sm2

import (
    "io"
    "errors"
    "strings"
    "math/big"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 使用自定义数据生成密钥对
func (this SM2) GenerateKeyWithSeed(reader io.Reader) SM2 {
    privateKey, err := sm2.GenerateKey(reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 使用自定义数据生成密钥对
func GenerateKeyWithSeed(reader io.Reader) SM2 {
    return defaultSM2.GenerateKeyWithSeed(reader)
}

// 生成密钥对
func (this SM2) GenerateKey() SM2 {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥对
func GenerateKey() SM2 {
    return defaultSM2.GenerateKey()
}

// ==========

// 私钥
func (this SM2) FromPrivateKey(key []byte) SM2 {
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
func FromPrivateKey(key []byte) SM2 {
    return defaultSM2.FromPrivateKey(key)
}

// 私钥带密码
func (this SM2) FromPrivateKeyWithPassword(key []byte, password string) SM2 {
    privateKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err == nil {
        this.privateKey = privateKey

        return this
    }

    privateKey, err = this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
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

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) SM2 {
    return defaultSM2.FromPrivateKeyWithPassword(key, password)
}

// ==========

// PKCS1 私钥
func (this SM2) FromPKCS1PrivateKey(key []byte) SM2 {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) SM2 {
    return defaultSM2.FromPKCS1PrivateKey(key)
}

// PKCS1 私钥带密码
func (this SM2) FromPKCS1PrivateKeyWithPassword(key []byte, password string) SM2 {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) SM2 {
    return defaultSM2.FromPKCS1PrivateKeyWithPassword(key, password)
}

// ==========

// PKCS8 私钥
func (this SM2) FromPKCS8PrivateKey(key []byte) SM2 {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) SM2 {
    return defaultSM2.FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func (this SM2) FromPKCS8PrivateKeyWithPassword(key []byte, password string) SM2 {
    var err error

    var privateKey *sm2.PrivateKey
    if privateKey, err = this.ParsePrivateKeyFromPEMWithPassword(key, password); err != nil {
        if privateKey, err = this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password); err != nil {
            return this.AppendError(err)
        }
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) SM2 {
    return defaultSM2.FromPKCS8PrivateKeyWithPassword(key, password)
}

// ==========

// 公钥，默认只有一种类型
func (this SM2) FromPublicKey(key []byte) SM2 {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥，默认只有一种类型
func FromPublicKey(key []byte) SM2 {
    return defaultSM2.FromPublicKey(key)
}

// ==========

// PKCS1 编码 DER 私钥
func (this SM2) FromPKCS1PrivateKeyDer(der []byte) SM2 {
    key := pem.EncodeToPEM(der, "SM2 PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 编码 DER 私钥
func (this SM2) FromPKCS8PrivateKeyDer(der []byte) SM2 {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// DER 公钥
func (this SM2) FromPublicKeyDer(der []byte) SM2 {
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
// [xString: xHexString, yString: yHexString]
func (this SM2) FromPublicKeyXYString(xString, yString string) SM2 {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &sm2.PublicKey{
        Curve: sm2.P256(),
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥 x,y 字节对
func (this SM2) FromPublicKeyXYBytes(XBytes, YBytes []byte) SM2 {
    x := new(big.Int).SetBytes(XBytes)
    y := new(big.Int).SetBytes(YBytes)

    this.publicKey = &sm2.PublicKey{
        Curve: sm2.P256(),
        X:     x,
        Y:     y,
    }

    return this
}

// ==========

// 公钥明文未压缩 (hexStringX + hexStringY)
// public-key: 047c********.
func (this SM2) FromPublicKeyUncompressString(keyString string) SM2 {
    if len(keyString) == 130 && strings.HasPrefix(keyString, "04") {
        keyString = strings.TrimPrefix(keyString, "04")
    }

    x, _ := new(big.Int).SetString(keyString[:64], 16)
    y, _ := new(big.Int).SetString(keyString[64:], 16)

    this.publicKey = &sm2.PublicKey{
        Curve: sm2.P256(),
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥明文压缩
// public-key: 027c******** || 036c********
// 0333B01B61D94A775DA72A0BFF9AB324DE672EA0977584D23AF34F8150223305B0
// 023613B13F252F6FB2374A85D93C7FFE9CCAD1231BE866F5FE69255312CE85B9FF
func (this SM2) FromPublicKeyCompressString(key string) SM2 {
    if len(key) != 66 || (!strings.HasPrefix(key, "02") && !strings.HasPrefix(key, "03")) {
        err := errors.New("Compress PublicKey prefix is 02 or 03.")
        return this.AppendError(err)
    }

    d, _ := new(big.Int).SetString(key[:], 16)

    publicKey, err := sm2.Decompress(d.Bytes())
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 公钥明文
func (this SM2) FromPublicKeyString(key string) SM2 {
    if len(key) == 66 {
        return this.FromPublicKeyCompressString(key)
    }

    return this.FromPublicKeyUncompressString(key)
}

// 私钥明文
// private-key: 07e4********;
func (this SM2) FromPrivateKeyString(keyString string) SM2 {
    c := sm2.P256()
    k, _ := new(big.Int).SetString(keyString[:], 16)

    priv := new(sm2.PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    this.privateKey = priv

    return this
}

// ==========

// 公钥明文, hex 或者 base64 解码后
func (this SM2) FromPublicKeyBytes(pubBytes []byte) SM2 {
    key := encoding.HexEncode(pubBytes)

    return this.FromPublicKeyString(key)
}

// 私钥明文, hex 或者 base64 解码后
func (this SM2) FromPrivateKeyBytes(priBytes []byte) SM2 {
    c := sm2.P256()
    k := new(big.Int).SetBytes(priBytes)

    priv := new(sm2.PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    this.privateKey = priv

    return this
}

// ==========

// 字节
func (this SM2) FromBytes(data []byte) SM2 {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) SM2 {
    return defaultSM2.FromBytes(data)
}

// 字符
func (this SM2) FromString(data string) SM2 {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) SM2 {
    return defaultSM2.FromString(data)
}

// Base64数据
func (this SM2) FromBase64String(data string) SM2 {
    newData, err := encoding.Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Base64数据
func FromBase64String(data string) SM2 {
    return defaultSM2.FromBase64String(data)
}

// 16进制数据
func (this SM2) FromHexString(data string) SM2 {
    newData, err := encoding.HexDecode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// 16进制数据
func FromHexString(data string) SM2 {
    return defaultSM2.FromHexString(data)
}
