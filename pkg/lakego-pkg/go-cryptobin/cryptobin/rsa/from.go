package rsa

import (
    "io"
    "errors"
    "math/big"
    "crypto/rsa"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool/pem"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func (this RSA) GenerateKeyWithSeed(reader io.Reader, bits int) RSA {
    privateKey, err := rsa.GenerateKey(reader, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func GenerateKeyWithSeed(reader io.Reader, bits int) RSA {
    return defaultRSA.GenerateKeyWithSeed(reader, bits)
}

// 生成密钥
func (this RSA) GenerateMultiPrimeKeyWithSeed(reader io.Reader, nprimes int, bits int) RSA {
    privateKey, err := rsa.GenerateMultiPrimeKey(reader, nprimes, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = &privateKey.PublicKey

    return this
}

// 生成密钥
func GenerateMultiPrimeKeyWithSeed(reader io.Reader, nprimes int, bits int) RSA {
    return defaultRSA.GenerateMultiPrimeKeyWithSeed(reader, nprimes, bits)
}

// ==========

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func (this RSA) GenerateKey(bits int) RSA {
    return this.GenerateKeyWithSeed(rand.Reader, bits)
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func GenerateKey(bits int) RSA {
    return defaultRSA.GenerateKey(bits)
}

// 生成密钥
func (this RSA) GenerateMultiPrimeKey(nprimes int, bits int) RSA {
    return this.GenerateMultiPrimeKeyWithSeed(rand.Reader, nprimes, bits)
}

// 生成密钥
func GenerateMultiPrimeKey(nprimes int, bits int) RSA {
    return defaultRSA.GenerateMultiPrimeKey(nprimes, bits)
}

// ==========

// 私钥
func (this RSA) FromPrivateKey(key []byte) RSA {
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
func FromPrivateKey(key []byte) RSA {
    return defaultRSA.FromPrivateKey(key)
}

// 私钥带密码
func (this RSA) FromPrivateKeyWithPassword(key []byte, password string) RSA {
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
func FromPrivateKeyWithPassword(key []byte, password string) RSA {
    return defaultRSA.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this RSA) FromPublicKey(key []byte) RSA {
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
func FromPublicKey(key []byte) RSA {
    return defaultRSA.FromPublicKey(key)
}

// ==========

// 模数、指数生成公钥
// 指数默认为 0x10001(65537)
func (this RSA) FromPublicKeyNE(nString string, eString string) RSA {
    n, ok := new(big.Int).SetString(nString[:], 16)
    if !ok {
        err := errors.New("n is error")
        return this.AppendError(err)
    }

    e, ok := new(big.Int).SetString(eString[:], 16)
    if !ok {
        err := errors.New("e is error")
        return this.AppendError(err)
    }

    this.publicKey = &rsa.PublicKey{
        N: n,
        E: int(e.Int64()),
    }

    return this
}

// 公钥
func FromPublicKeyNE(nString string, eString string) RSA {
    return defaultRSA.FromPublicKeyNE(nString, eString)
}

// ==========

// Pkcs1
func (this RSA) FromPKCS1PrivateKey(key []byte) RSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) RSA {
    return defaultRSA.FromPKCS1PrivateKey(key)
}

// Pkcs1WithPassword
func (this RSA) FromPKCS1PrivateKeyWithPassword(key []byte, password string) RSA {
    privateKey, err := this.ParsePKCS1PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) RSA {
    return defaultRSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// PKCS1 公钥
func (this RSA) FromPKCS1PublicKey(key []byte) RSA {
    publicKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) RSA {
    return defaultRSA.FromPKCS1PublicKey(key)
}

// ==========

// Pkcs8
func (this RSA) FromPKCS8PrivateKey(key []byte) RSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) RSA {
    return defaultRSA.FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func (this RSA) FromPKCS8PrivateKeyWithPassword(key []byte, password string) RSA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) RSA {
    return defaultRSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func (this RSA) FromPKCS8PublicKey(key []byte) RSA {
    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) RSA {
    return defaultRSA.FromPKCS8PublicKey(key)
}

// ==========

// Pkcs1 DER
func (this RSA) FromPKCS1PrivateKeyDer(der []byte) RSA {
    key := pem.EncodeToPEM(der, "RSA PRIVATE KEY")

    privateKey, err := this.ParsePKCS1PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS1 DER 公钥
func (this RSA) FromPKCS1PublicKeyDer(der []byte) RSA {
    key := pem.EncodeToPEM(der, "RSA PUBLIC KEY")

    publicKey, err := this.ParsePKCS1PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// ==========

// Pkcs8 DER
func (this RSA) FromPKCS8PrivateKeyDer(der []byte) RSA {
    key := pem.EncodeToPEM(der, "PRIVATE KEY")

    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// PKCS8 DER 公钥
func (this RSA) FromPKCS8PublicKeyDer(der []byte) RSA {
    key := pem.EncodeToPEM(der, "PUBLIC KEY")

    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// ==========

// XML 私钥
func (this RSA) FromXMLPrivateKey(key []byte) RSA {
    privateKey, err := this.ParsePrivateKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// XML 私钥
func FromXMLPrivateKey(key []byte) RSA {
    return defaultRSA.FromXMLPrivateKey(key)
}

// XML 公钥
func (this RSA) FromXMLPublicKey(key []byte) RSA {
    publicKey, err := this.ParsePublicKeyFromXML(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// XML 公钥
func FromXMLPublicKey(key []byte) RSA {
    return defaultRSA.FromXMLPublicKey(key)
}

// ==========

// Pkcs12 Cert
func (this RSA) FromPKCS12Cert(key []byte) RSA {
    privateKey, err := this.ParsePKCS12CertFromPEMWithPassword(key, "")
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// Pkcs12Cert
func FromPKCS12Cert(key []byte) RSA {
    return defaultRSA.FromPKCS12Cert(key)
}

// Pkcs12CertWithPassword
func (this RSA) FromPKCS12CertWithPassword(key []byte, password string) RSA {
    privateKey, err := this.ParsePKCS12CertFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// Pkcs12Cert 带密码
func FromPKCS12CertWithPassword(key []byte, password string) RSA {
    return defaultRSA.FromPKCS12CertWithPassword(key, password)
}

// ==========

// 字节
func (this RSA) FromBytes(data []byte) RSA {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) RSA {
    return defaultRSA.FromBytes(data)
}

// 字符
func (this RSA) FromString(data string) RSA {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) RSA {
    return defaultRSA.FromString(data)
}

// Base64
func (this RSA) FromBase64String(data string) RSA {
    newData, err := encoding.Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Base64
func FromBase64String(data string) RSA {
    return defaultRSA.FromBase64String(data)
}

// Hex
func (this RSA) FromHexString(data string) RSA {
    newData, err := encoding.HexDecode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Hex
func FromHexString(data string) RSA {
    return defaultRSA.FromHexString(data)
}
