package cryptobin

import (
    "strings"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
)

// 私钥
func (this Ecdsa) FromPrivateKey(key []byte) Ecdsa {
    this.privateKey, this.Error = this.ParseECPrivateKeyFromPEM(key)

    return this
}

// 私钥带密码
func (this Ecdsa) FromPrivateKeyWithPassword(key []byte, password string) Ecdsa {
    this.privateKey, this.Error = this.ParseECPrivateKeyFromPEMWithPassword(key, password)

    return this
}

// PKCS8 私钥
func (this Ecdsa) FromPKCS8PrivateKey(key []byte) Ecdsa {
    this.privateKey, this.Error = this.ParseECPrivateKeyFromPEM(key)

    return this
}

// Pkcs8WithPassword
func (this Ecdsa) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Ecdsa {
    this.privateKey, this.Error = this.ParseECPKCS8PrivateKeyFromPEMWithPassword(key, password)

    return this
}

// 公钥
func (this Ecdsa) FromPublicKey(key []byte) Ecdsa {
    this.publicKey, this.Error = this.ParseECPublicKeyFromPEM(key)

    return this
}

// 生成密钥
func (this Ecdsa) GenerateKey() Ecdsa {
    this.privateKey, this.Error = ecdsa.GenerateKey(this.curve, rand.Reader)

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// ==========

// 公钥字符 (hexStringX + hexStringY)
func (this Ecdsa) FromPublicKeyString(keyString string) Ecdsa {
    if len(keyString) == 130 && strings.HasPrefix(keyString, "04") {
        keyString = strings.TrimPrefix(keyString, "04")
    }

    publicKeyStr := strings.TrimLeft(keyString, "0")

    x, _ := new(big.Int).SetString(publicKeyStr[:64], 16)
    y, _ := new(big.Int).SetString(publicKeyStr[64:], 16)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 私钥字符，必须先添加公钥 (hexStringD)
func (this Ecdsa) FromPrivateKeyString(keyString string) Ecdsa {
    privateKeyStr := strings.TrimLeft(keyString, "0")
    d, _ := new(big.Int).SetString(privateKeyStr[:], 16)

    this.privateKey = &ecdsa.PrivateKey{
        PublicKey: *this.publicKey,
        D:         d,
    }

    return this
}

// ==========

// 公钥字符对
func (this Ecdsa) FromPublicKeyXYBytes(XBytes, YBytes []byte) Ecdsa {
    x := new(big.Int).SetBytes(XBytes)
    y := new(big.Int).SetBytes(YBytes)

    this.publicKey = &ecdsa.PublicKey{
        Curve: this.curve,
        X:     x,
        Y:     y,
    }

    return this
}

// 私钥字符，必须先添加公钥
func (this Ecdsa) FromPrivateKeyDBytes(DBytes []byte) Ecdsa {
    d := new(big.Int).SetBytes(DBytes)

    this.privateKey = &ecdsa.PrivateKey{
        PublicKey: *this.publicKey,
        D:         d,
    }

    return this
}

// ==========

// 明文私钥生成私钥结构体
func (this Ecdsa) FromPrivateKeyBytes(priByte []byte) Ecdsa {
    c := this.curve
    k := new(big.Int).SetBytes(priByte)

    priv := new(ecdsa.PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    this.privateKey = priv

    // 同时生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// ==========

// 字节
func (this Ecdsa) FromBytes(data []byte) Ecdsa {
    this.data = data

    return this
}

// 字符
func (this Ecdsa) FromString(data string) Ecdsa {
    this.data = []byte(data)

    return this
}

// Base64
func (this Ecdsa) FromBase64String(data string) Ecdsa {
    this.data, this.Error = NewEncoding().Base64Decode(data)

    return this
}

// Hex
func (this Ecdsa) FromHexString(data string) Ecdsa {
    this.data, this.Error = NewEncoding().HexDecode(data)

    return this
}
