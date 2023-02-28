package dsa

import (
    "crypto/dsa"
    "crypto/rand"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this DSA) FromPrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// 私钥带密码
func (this DSA) FromPrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// 公钥
func (this DSA) FromPublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func (this DSA) GenerateKey(ln string) DSA {
    var paramSize dsa.ParameterSizes

    // 算法类型
    switch ln {
        case "L1024N160":
            paramSize = dsa.L1024N160
        case "L2048N224":
            paramSize = dsa.L2048N224
        case "L2048N256":
            paramSize = dsa.L2048N256
        case "L3072N256":
            paramSize = dsa.L3072N256
        default:
            paramSize = dsa.L1024N160
    }

    priv := &dsa.PrivateKey{}
    dsa.GenerateParameters(&priv.Parameters, rand.Reader, paramSize)
    dsa.GenerateKey(priv, rand.Reader)

    this.privateKey = priv
    this.publicKey = &priv.PublicKey

    return this
}

// ==========

// PKCS8 私钥
func (this DSA) FromPKCS8PrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥带密码
func (this DSA) FromPKCS8PrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 公钥
func (this DSA) FromPKCS8PublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// 字节
func (this DSA) FromBytes(data []byte) DSA {
    this.data = data

    return this
}

// 字符
func (this DSA) FromString(data string) DSA {
    this.data = []byte(data)

    return this
}

// Base64
func (this DSA) FromBase64String(data string) DSA {
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func (this DSA) FromHexString(data string) DSA {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}
