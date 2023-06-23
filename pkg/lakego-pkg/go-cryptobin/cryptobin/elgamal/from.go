package elgamal

import (
    "crypto/rand"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
    cryptobin_elgamal "github.com/deatil/go-cryptobin/elgamal"
)

// 私钥
func (this EIGamal) FromPrivateKey(key []byte) EIGamal {
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
func FromPrivateKey(key []byte) EIGamal {
    return defaultEIGamal.FromPrivateKey(key)
}

// 私钥带密码
func (this EIGamal) FromPrivateKeyWithPassword(key []byte, password string) EIGamal {
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
func FromPrivateKeyWithPassword(key []byte, password string) EIGamal {
    return defaultEIGamal.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this EIGamal) FromPublicKey(key []byte) EIGamal {
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
func FromPublicKey(key []byte) EIGamal {
    return defaultEIGamal.FromPublicKey(key)
}

// ==========

// 生成密钥
func (this EIGamal) GenerateKey(bitsize, probability int) EIGamal {
    priv, err := cryptobin_elgamal.GenerateKey(rand.Reader, bitsize, probability)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = priv
    this.publicKey = &priv.PublicKey

    return this
}

// 生成密钥
func GenerateKey(bitsize, probability int) EIGamal {
    return defaultEIGamal.GenerateKey(bitsize, probability)
}

// ==========

// PKCS1 私钥
func (this EIGamal) FromPKCS1PrivateKey(key []byte) EIGamal {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) EIGamal {
    return defaultEIGamal.FromPKCS1PrivateKey(key)
}

// PKCS1 私钥带密码
func (this EIGamal) FromPKCS1PrivateKeyWithPassword(key []byte, password string) EIGamal {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) EIGamal {
    return defaultEIGamal.FromPKCS1PrivateKeyWithPassword(key, password)
}

// PKCS1 公钥
func (this EIGamal) FromPKCS1PublicKey(key []byte) EIGamal {
    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) EIGamal {
    return defaultEIGamal.FromPKCS1PublicKey(key)
}

// ==========

// PKCS8 私钥
func (this EIGamal) FromPKCS8PrivateKey(key []byte) EIGamal {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) EIGamal {
    return defaultEIGamal.FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func (this EIGamal) FromPKCS8PrivateKeyWithPassword(key []byte, password string) EIGamal {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) EIGamal {
    return defaultEIGamal.FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func (this EIGamal) FromPKCS8PublicKey(key []byte) EIGamal {
    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) EIGamal {
    return defaultEIGamal.FromPKCS8PublicKey(key)
}

// ==========

// Pkcs1 DER 私钥
func (this EIGamal) FromPKCS1PrivateKeyDer(der []byte) EIGamal {
    key := cryptobin_tool.EncodeDerToPem(der, "EIGamal PRIVATE KEY")

    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 DER 公钥
func (this EIGamal) FromPKCS1PublicKeyDer(der []byte) EIGamal {
    key := cryptobin_tool.EncodeDerToPem(der, "EIGamal PUBLIC KEY")

    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// Pkcs8 DER 私钥
func (this EIGamal) FromPKCS8PrivateKeyDer(der []byte) EIGamal {
    key := cryptobin_tool.EncodeDerToPem(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 DER 公钥
func (this EIGamal) FromPKCS8PublicKeyDer(der []byte) EIGamal {
    key := cryptobin_tool.EncodeDerToPem(der, "PUBLIC KEY")

    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// XML 私钥
func (this EIGamal) FromXMLPrivateKey(key []byte) EIGamal {
    privateKey, err := this.ParsePrivateKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// XML 私钥
func FromXMLPrivateKey(key []byte) EIGamal {
    return defaultEIGamal.FromXMLPrivateKey(key)
}

// XML 公钥
func (this EIGamal) FromXMLPublicKey(key []byte) EIGamal {
    publicKey, err := this.ParsePublicKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// XML 公钥
func FromXMLPublicKey(key []byte) EIGamal {
    return defaultEIGamal.FromXMLPublicKey(key)
}

// ==========

// 字节
func (this EIGamal) FromBytes(data []byte) EIGamal {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) EIGamal {
    return defaultEIGamal.FromBytes(data)
}

// 字符
func (this EIGamal) FromString(data string) EIGamal {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) EIGamal {
    return defaultEIGamal.FromString(data)
}

// Base64
func (this EIGamal) FromBase64String(data string) EIGamal {
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) EIGamal {
    return defaultEIGamal.FromBase64String(data)
}

// Hex
func (this EIGamal) FromHexString(data string) EIGamal {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) EIGamal {
    return defaultEIGamal.FromHexString(data)
}
