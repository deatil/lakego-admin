package rsa

import (
    "io"
    "errors"
    "math/big"
    "crypto/rsa"
    "crypto/rand"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func (this Rsa) GenerateKey(bits int) Rsa {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func GenerateKey(bits int) Rsa {
    return defaultRSA.GenerateKey(bits)
}

// 生成密钥
func (this Rsa) GenerateMultiPrimeKey(nprimes int, bits int) Rsa {
    privateKey, err := rsa.GenerateMultiPrimeKey(rand.Reader, nprimes, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥
func GenerateMultiPrimeKey(nprimes int, bits int) Rsa {
    return defaultRSA.GenerateMultiPrimeKey(nprimes, bits)
}

// ==========

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func (this Rsa) GenerateKeyWithSeed(reader io.Reader, bits int) Rsa {
    privateKey, err := rsa.GenerateKey(reader, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func GenerateKeyWithSeed(reader io.Reader, bits int) Rsa {
    return defaultRSA.GenerateKeyWithSeed(reader, bits)
}

// 生成密钥
func (this Rsa) GenerateMultiPrimeKeyWithSeed(reader io.Reader, nprimes int, bits int) Rsa {
    privateKey, err := rsa.GenerateMultiPrimeKey(reader, nprimes, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥
func GenerateMultiPrimeKeyWithSeed(reader io.Reader, nprimes int, bits int) Rsa {
    return defaultRSA.GenerateMultiPrimeKeyWithSeed(reader, nprimes, bits)
}

// ==========

// 私钥
func (this Rsa) FromPrivateKey(key []byte) Rsa {
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
func FromPrivateKey(key []byte) Rsa {
    return defaultRSA.FromPrivateKey(key)
}

// 私钥带密码
func (this Rsa) FromPrivateKeyWithPassword(key []byte, password string) Rsa {
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

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this Rsa) FromPublicKey(key []byte) Rsa {
    var publicKey *rsa.PublicKey
    var err error

    publicKey, err = this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        publicKey, err = this.ParsePKCS1PublicKeyFromPEM(key)
        if err != nil {
            return this.AppendError(err)
        }
    }

    this.publicKey = publicKey

    return this
}

// 公钥
func FromPublicKey(key []byte) Rsa {
    return defaultRSA.FromPublicKey(key)
}

// ==========

// 模数、指数生成公钥
// 指数默认为 0x10001(65537)
func (this Rsa) FromPublicKeyNE(nString string, eString string) Rsa {
    n, ok := new(big.Int).SetString(nString[:], 16)
    if !ok {
        err := errors.New("RSA: n is error")
        return this.AppendError(err)
    }

    e, ok := new(big.Int).SetString(eString[:], 16)
    if !ok {
        err := errors.New("RSA: e is error")
        return this.AppendError(err)
    }

    this.publicKey = &rsa.PublicKey{
        N: n,
        E: int(e.Int64()),
    }

    return this
}

// 公钥
func FromPublicKeyNE(nString string, eString string) Rsa {
    return defaultRSA.FromPublicKeyNE(nString, eString)
}

// ==========

// Pkcs1
func (this Rsa) FromPKCS1PrivateKey(key []byte) Rsa {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) Rsa {
    return defaultRSA.FromPKCS1PrivateKey(key)
}

// Pkcs1WithPassword
func (this Rsa) FromPKCS1PrivateKeyWithPassword(key []byte, password string) Rsa {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// PKCS1 公钥
func (this Rsa) FromPKCS1PublicKey(key []byte) Rsa {
    publicKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) Rsa {
    return defaultRSA.FromPKCS1PublicKey(key)
}

// ==========

// Pkcs8
func (this Rsa) FromPKCS8PrivateKey(key []byte) Rsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Rsa {
    return defaultRSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this Rsa) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Rsa {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func (this Rsa) FromPKCS8PublicKey(key []byte) Rsa {
    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) Rsa {
    return defaultRSA.FromPKCS8PublicKey(key)
}

// ==========

// Pkcs1 DER
func (this Rsa) FromPKCS1PrivateKeyDer(der []byte) Rsa {
    key := cryptobin_tool.EncodeDerToPem(der, "RSA PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 DER 公钥
func (this Rsa) FromPKCS1PublicKeyDer(der []byte) Rsa {
    key := cryptobin_tool.EncodeDerToPem(der, "RSA PUBLIC KEY")

    publicKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// ==========

// Pkcs8 DER
func (this Rsa) FromPKCS8PrivateKeyDer(der []byte) Rsa {
    key := cryptobin_tool.EncodeDerToPem(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 DER 公钥
func (this Rsa) FromPKCS8PublicKeyDer(der []byte) Rsa {
    key := cryptobin_tool.EncodeDerToPem(der, "PUBLIC KEY")

    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// ==========

// XML 私钥
func (this Rsa) FromXMLPrivateKey(key []byte) Rsa {
    privateKey, err := this.ParsePrivateKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// XML 私钥
func FromXMLPrivateKey(key []byte) Rsa {
    return defaultRSA.FromXMLPrivateKey(key)
}

// XML 公钥
func (this Rsa) FromXMLPublicKey(key []byte) Rsa {
    publicKey, err := this.ParsePublicKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// XML 公钥
func FromXMLPublicKey(key []byte) Rsa {
    return defaultRSA.FromXMLPublicKey(key)
}

// ==========

// Pkcs12 Cert
func (this Rsa) FromPKCS12Cert(key []byte) Rsa {
    privateKey, err := this.ParsePKCS12CertFromPEMWithPassword(key, "")
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// Pkcs12Cert
func FromPKCS12Cert(key []byte) Rsa {
    return defaultRSA.FromPKCS12Cert(key)
}

// Pkcs12CertWithPassword
func (this Rsa) FromPKCS12CertWithPassword(key []byte, password string) Rsa {
    privateKey, err := this.ParsePKCS12CertFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// Pkcs12Cert 带密码
func FromPKCS12CertWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPKCS12CertWithPassword(key, password)
}

// ==========

// 字节
func (this Rsa) FromBytes(data []byte) Rsa {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Rsa {
    return defaultRSA.FromBytes(data)
}

// 字符
func (this Rsa) FromString(data string) Rsa {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Rsa {
    return defaultRSA.FromString(data)
}

// Base64
func (this Rsa) FromBase64String(data string) Rsa {
    newData, err := cryptobin_tool.NewEncoding().Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Base64
func FromBase64String(data string) Rsa {
    return defaultRSA.FromBase64String(data)
}

// Hex
func (this Rsa) FromHexString(data string) Rsa {
    newData, err := cryptobin_tool.NewEncoding().HexDecode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Hex
func FromHexString(data string) Rsa {
    return defaultRSA.FromHexString(data)
}
