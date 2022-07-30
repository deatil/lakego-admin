package rsa

// 构造函数
func NewRsa() Rsa {
    return Rsa{
        veryed:   false,
        signHash: "SHA512",
    }
}

// ==========

// 私钥
func RsaFromPrivateKey(key []byte) Rsa {
    return NewRsa().FromPrivateKey(key)
}

// 私钥带密码
func RsaFromPrivateKeyWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func RsaFromPublicKey(key []byte) Rsa {
    return NewRsa().FromPublicKey(key)
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func RsaGenerateKey(bits int) Rsa {
    return NewRsa().GenerateKey(bits)
}

// ==========

// Pkcs1
func RsaFromPKCS1PrivateKey(key []byte) Rsa {
    return NewRsa().FromPKCS1PrivateKey(key)
}

// Pkcs1WithPassword
func RsaFromPKCS1PrivateKeyWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPKCS1PrivateKeyWithPassword(key, password)
}

// Pkcs8
func RsaFromPKCS8PrivateKey(key []byte) Rsa {
    return NewRsa().FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func RsaFromPKCS8PrivateKeyWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPKCS8PrivateKeyWithPassword(key, password)
}

// Pkcs12 Cert
func RsaFromPKCS12Cert(key []byte) Rsa {
    return NewRsa().FromPKCS12Cert(key)
}

// Pkcs12CertWithPassword
func RsaFromPKCS12CertWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPKCS12CertWithPassword(key, password)
}

// ==========

// 字节
func RsaFromBytes(data []byte) Rsa {
    return NewRsa().FromBytes(data)
}

// 字符
func RsaFromString(data string) Rsa {
    return NewRsa().FromString(data)
}

// Base64
func RsaFromBase64String(data string) Rsa {
    return NewRsa().FromBase64String(data)
}

// Hex
func RsaFromHexString(data string) Rsa {
    return NewRsa().FromHexString(data)
}
