package sm2

import (
    "strings"
    "math/big"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this SM2) FromPrivateKey(key []byte) SM2 {
    privateKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// 私钥带密码
func (this SM2) FromPrivateKeyWithPassword(key []byte, password string) SM2 {
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

// 公钥
func (this SM2) FromPublicKey(key []byte) SM2 {
    publicKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 生成密钥
func (this SM2) GenerateKey() SM2 {
    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// ==========

// 公钥字符 (hexStringX + hexStringY)
// public-key: 047c********.
func (this SM2) FromPublicKeyString(keyString string) SM2 {
    if len(keyString) == 130 && strings.HasPrefix(keyString, "04") {
        keyString = strings.TrimPrefix(keyString, "04")
    }

    x, _ := new(big.Int).SetString(keyString[:64], 16)
    y, _ := new(big.Int).SetString(keyString[64:], 16)

    this.publicKey = &sm2.PublicKey{
        Curve: sm2.P256Sm2(),
        X:     x,
        Y:     y,
    }

    return this
}

// 公钥 x,y 16进制字符对
// [xString: xHexString, yString: yHexString]
func (this SM2) FromPublicKeyXYString(xString string, yString string) SM2 {
    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    this.publicKey = &sm2.PublicKey{
        Curve: sm2.P256Sm2(),
        X:     x,
        Y:     y,
    }

    return this
}

// 私钥字符，必须先添加公钥 (hexStringD)
// private-key: 07e4********;
func (this SM2) FromPrivateKeyString(keyString string) SM2 {
    d, _ := new(big.Int).SetString(keyString[:], 16)

    this.privateKey = &sm2.PrivateKey{
        PublicKey: *this.publicKey,
        D:         d,
    }

    return this
}

// ==========

// 公钥字符对
func (this SM2) FromPublicKeyXYBytes(XBytes, YBytes []byte) SM2 {
    x := new(big.Int).SetBytes(XBytes)
    y := new(big.Int).SetBytes(YBytes)

    this.publicKey = &sm2.PublicKey{
        Curve: sm2.P256Sm2(),
        X:     x,
        Y:     y,
    }

    return this
}

// 私钥字符，必须先添加公钥
func (this SM2) FromPrivateKeyDBytes(DBytes []byte) SM2 {
    d := new(big.Int).SetBytes(DBytes)

    this.privateKey = &sm2.PrivateKey{
        PublicKey: *this.publicKey,
        D:         d,
    }

    return this
}

// ==========

// 明文私钥生成私钥结构体
func (this SM2) FromPrivateKeyBytes(priByte []byte) SM2 {
    c := sm2.P256Sm2()
    k := new(big.Int).SetBytes(priByte)

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

// 字符
func (this SM2) FromString(data string) SM2 {
    this.data = []byte(data)

    return this
}

// Base64
func (this SM2) FromBase64String(data string) SM2 {
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Hex
func (this SM2) FromHexString(data string) SM2 {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}
