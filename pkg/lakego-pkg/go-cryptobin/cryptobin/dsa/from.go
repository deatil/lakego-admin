package dsa

import (
    "io"
    "crypto/dsa"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func (this DSA) GenerateKeyWithSeed(paramReader, generateReader io.Reader, ln string) DSA {
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
    dsa.GenerateParameters(&priv.Parameters, paramReader, paramSize)
    dsa.GenerateKey(priv, generateReader)

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func GenerateKeyWithSeed(paramReader, generateReader io.Reader, ln string) DSA {
    return defaultDSA.GenerateKeyWithSeed(paramReader, generateReader, ln)
}

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func (this DSA) GenerateKey(ln string) DSA {
    return this.GenerateKeyWithSeed(rand.Reader, rand.Reader, ln)
}

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func GenerateKey(ln string) DSA {
    return defaultDSA.GenerateKey(ln)
}

// ==========

// 私钥
func (this DSA) FromPrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err == nil {
        this.privateKey = parsedKey

        return this
    }

    parsedKey, err = this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// 私钥
func FromPrivateKey(key []byte) DSA {
    return defaultDSA.FromPrivateKey(key)
}

// 私钥带密码
func (this DSA) FromPrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err == nil {
        this.privateKey = parsedKey

        return this
    }

    parsedKey, err = this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) DSA {
    return defaultDSA.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this DSA) FromPublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err == nil {
        this.publicKey = parsedKey

        return this
    }

    parsedKey, err = this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// 公钥
func FromPublicKey(key []byte) DSA {
    return defaultDSA.FromPublicKey(key)
}

// ==========

// PKCS1 私钥
func (this DSA) FromPKCS1PrivateKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) DSA {
    return defaultDSA.FromPKCS1PrivateKey(key)
}

// PKCS1 私钥带密码
func (this DSA) FromPKCS1PrivateKeyWithPassword(key []byte, password string) DSA {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) DSA {
    return defaultDSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// PKCS1 公钥
func (this DSA) FromPKCS1PublicKey(key []byte) DSA {
    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) DSA {
    return defaultDSA.FromPKCS1PublicKey(key)
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

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) DSA {
    return defaultDSA.FromPKCS8PrivateKey(key)
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

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) DSA {
    return defaultDSA.FromPKCS8PrivateKeyWithPassword(key, password)
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

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) DSA {
    return defaultDSA.FromPKCS8PublicKey(key)
}

// ==========

// Pkcs1 DER 私钥
func (this DSA) FromPKCS1PrivateKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "DSA PRIVATE KEY")

    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 DER 公钥
func (this DSA) FromPKCS1PublicKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "DSA PUBLIC KEY")

    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// Pkcs8 DER 私钥
func (this DSA) FromPKCS8PrivateKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 DER 公钥
func (this DSA) FromPKCS8PublicKeyDer(der []byte) DSA {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// XML 私钥
func (this DSA) FromXMLPrivateKey(key []byte) DSA {
    privateKey, err := this.ParsePrivateKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// XML 私钥
func FromXMLPrivateKey(key []byte) DSA {
    return defaultDSA.FromXMLPrivateKey(key)
}

// XML 公钥
func (this DSA) FromXMLPublicKey(key []byte) DSA {
    publicKey, err := this.ParsePublicKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// XML 公钥
func FromXMLPublicKey(key []byte) DSA {
    return defaultDSA.FromXMLPublicKey(key)
}

// ==========

// 字节
func (this DSA) FromBytes(data []byte) DSA {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) DSA {
    return defaultDSA.FromBytes(data)
}

// 字符
func (this DSA) FromString(data string) DSA {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) DSA {
    return defaultDSA.FromString(data)
}

// Base64
func (this DSA) FromBase64String(data string) DSA {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) DSA {
    return defaultDSA.FromBase64String(data)
}

// Hex
func (this DSA) FromHexString(data string) DSA {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) DSA {
    return defaultDSA.FromHexString(data)
}
