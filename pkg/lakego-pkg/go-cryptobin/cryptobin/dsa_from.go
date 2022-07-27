package cryptobin

import (
    "crypto/dsa"
    "crypto/rand"
)

// 私钥
func (this DSA) FromPrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey

    return this
}

// 私钥带密码
func (this DSA) FromPrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey

    return this
}

// 公钥
func (this DSA) FromPublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
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
    this.data, this.Error = NewEncoding().Base64Decode(data)

    return this
}

// Hex
func (this DSA) FromHexString(data string) DSA {
    this.data, this.Error = NewEncoding().HexDecode(data)

    return this
}
