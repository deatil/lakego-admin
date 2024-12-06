package elgamal

import (
    "io"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
)

// 使用数据生成密钥对
func (this ElGamal) GenerateKeyWithSeed(reader io.Reader, bitsize, probability int) ElGamal {
    privateKey, err := elgamal.GenerateKey(reader, bitsize, probability)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 使用数据生成密钥对
func GenerateKeyWithSeed(reader io.Reader, bitsize, probability int) ElGamal {
    return defaultElGamal.GenerateKeyWithSeed(reader, bitsize, probability)
}

// 生成密钥
func (this ElGamal) GenerateKey(bitsize, probability int) ElGamal {
    return this.GenerateKeyWithSeed(rand.Reader, bitsize, probability)
}

// 生成密钥
func GenerateKey(bitsize, probability int) ElGamal {
    return defaultElGamal.GenerateKey(bitsize, probability)
}

// ==========

// 私钥
func (this ElGamal) FromPrivateKey(key []byte) ElGamal {
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
func FromPrivateKey(key []byte) ElGamal {
    return defaultElGamal.FromPrivateKey(key)
}

// 私钥带密码
func (this ElGamal) FromPrivateKeyWithPassword(key []byte, password string) ElGamal {
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
func FromPrivateKeyWithPassword(key []byte, password string) ElGamal {
    return defaultElGamal.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this ElGamal) FromPublicKey(key []byte) ElGamal {
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
func FromPublicKey(key []byte) ElGamal {
    return defaultElGamal.FromPublicKey(key)
}

// ==========

// PKCS1 私钥
func (this ElGamal) FromPKCS1PrivateKey(key []byte) ElGamal {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) ElGamal {
    return defaultElGamal.FromPKCS1PrivateKey(key)
}

// PKCS1 私钥带密码
func (this ElGamal) FromPKCS1PrivateKeyWithPassword(key []byte, password string) ElGamal {
    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) ElGamal {
    return defaultElGamal.FromPKCS1PrivateKeyWithPassword(key, password)
}

// PKCS1 公钥
func (this ElGamal) FromPKCS1PublicKey(key []byte) ElGamal {
    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) ElGamal {
    return defaultElGamal.FromPKCS1PublicKey(key)
}

// ==========

// PKCS8 私钥
func (this ElGamal) FromPKCS8PrivateKey(key []byte) ElGamal {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) ElGamal {
    return defaultElGamal.FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func (this ElGamal) FromPKCS8PrivateKeyWithPassword(key []byte, password string) ElGamal {
    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) ElGamal {
    return defaultElGamal.FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func (this ElGamal) FromPKCS8PublicKey(key []byte) ElGamal {
    parsedKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) ElGamal {
    return defaultElGamal.FromPKCS8PublicKey(key)
}

// ==========

// Pkcs1 DER 私钥
func (this ElGamal) FromPKCS1PrivateKeyDer(der []byte) ElGamal {
    key := pem.EncodeToPEM(der, "ElGamal PRIVATE KEY")

    parsedKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS1 DER 公钥
func (this ElGamal) FromPKCS1PublicKeyDer(der []byte) ElGamal {
    key := pem.EncodeToPEM(der, "ElGamal PUBLIC KEY")

    parsedKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey

    return this
}

// ==========

// Pkcs8 DER 私钥
func (this ElGamal) FromPKCS8PrivateKeyDer(der []byte) ElGamal {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    parsedKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey

    return this
}

// PKCS8 DER 公钥
func (this ElGamal) FromPKCS8PublicKeyDer(der []byte) ElGamal {
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
func (this ElGamal) FromXMLPrivateKey(key []byte) ElGamal {
    privateKey, err := this.ParsePrivateKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// XML 私钥
func FromXMLPrivateKey(key []byte) ElGamal {
    return defaultElGamal.FromXMLPrivateKey(key)
}

// XML 公钥
func (this ElGamal) FromXMLPublicKey(key []byte) ElGamal {
    publicKey, err := this.ParsePublicKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// XML 公钥
func FromXMLPublicKey(key []byte) ElGamal {
    return defaultElGamal.FromXMLPublicKey(key)
}

// ==========

// 字节
func (this ElGamal) FromBytes(data []byte) ElGamal {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) ElGamal {
    return defaultElGamal.FromBytes(data)
}

// 字符
func (this ElGamal) FromString(data string) ElGamal {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) ElGamal {
    return defaultElGamal.FromString(data)
}

// Base64
func (this ElGamal) FromBase64String(data string) ElGamal {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) ElGamal {
    return defaultElGamal.FromBase64String(data)
}

// Hex
func (this ElGamal) FromHexString(data string) ElGamal {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) ElGamal {
    return defaultElGamal.FromHexString(data)
}
