package rsa

import (
    "math/big"
    "crypto/rsa"
    "crypto/rand"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥
func (this Rsa) FromPrivateKey(key []byte) Rsa {
    this.privateKey, this.Error = this.ParseRSAPrivateKeyFromPEM(key)

    return this
}

// 私钥带密码
func (this Rsa) FromPrivateKeyWithPassword(key []byte, password string) Rsa {
    privateKey, err := this.ParseRSAPKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err == nil {
        this.privateKey = privateKey

        return this
    }

    this.privateKey, this.Error = this.ParseRSAPrivateKeyFromPEMWithPassword(key, password)

    return this
}

// 公钥
func (this Rsa) FromPublicKey(key []byte) Rsa {
    this.publicKey, this.Error = this.ParseRSAPublicKeyFromPEM(key)

    return this
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func (this Rsa) GenerateKey(bits int) Rsa {
    this.privateKey, this.Error = rsa.GenerateKey(rand.Reader, bits)

    // 生成公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// ==========

// 模数、指数生成公钥
// 指数默认为 10001
func (this Rsa) FromPublicKeyNE(nString string, e int) Rsa {
    n, _ := new(big.Int).SetString(nString[:], 16)

    this.publicKey = &rsa.PublicKey{
        N: n,
        E: e,
    }

    return this
}

// ==========

// Pkcs1
func (this Rsa) FromPKCS1PrivateKey(key []byte) Rsa {
    this.privateKey, this.Error = this.ParseRSAPrivateKeyFromPEM(key)

    return this
}

// Pkcs1WithPassword
func (this Rsa) FromPKCS1PrivateKeyWithPassword(key []byte, password string) Rsa {
    this.privateKey, this.Error = this.ParseRSAPrivateKeyFromPEMWithPassword(key, password)

    return this
}

// Pkcs8
func (this Rsa) FromPKCS8PrivateKey(key []byte) Rsa {
    this.privateKey, this.Error = this.ParseRSAPrivateKeyFromPEM(key)

    return this
}

// Pkcs8WithPassword
func (this Rsa) FromPKCS8PrivateKeyWithPassword(key []byte, password string) Rsa {
    this.privateKey, this.Error = this.ParseRSAPKCS8PrivateKeyFromPEMWithPassword(key, password)

    return this
}

// Pkcs12 Cert
func (this Rsa) FromPKCS12Cert(key []byte) Rsa {
    this.privateKey, this.Error = this.ParseRSAPKCS12CertFromPEMWithPassword(key, "")

    return this
}

// Pkcs12CertWithPassword
func (this Rsa) FromPKCS12CertWithPassword(key []byte, password string) Rsa {
    this.privateKey, this.Error = this.ParseRSAPKCS12CertFromPEMWithPassword(key, password)

    return this
}

// ==========

// 字节
func (this Rsa) FromBytes(data []byte) Rsa {
    this.data = data

    return this
}

// 字符
func (this Rsa) FromString(data string) Rsa {
    this.data = []byte(data)

    return this
}

// Base64
func (this Rsa) FromBase64String(data string) Rsa {
    this.data, this.Error = cryptobin_tool.NewEncoding().Base64Decode(data)

    return this
}

// Hex
func (this Rsa) FromHexString(data string) Rsa {
    this.data, this.Error = cryptobin_tool.NewEncoding().HexDecode(data)

    return this
}
