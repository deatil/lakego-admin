package rsa

// 构造函数
func NewRsa() Rsa {
    return Rsa{
        signHash: "SHA512",
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Rsa {
    return NewRsa()
}

// ==========

// 私钥
func FromPrivateKey(key []byte) Rsa {
    return NewRsa().FromPrivateKey(key)
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) Rsa {
    return NewRsa().FromPublicKey(key)
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) Rsa {
    return NewRsa().FromPKCS1PublicKey(key)
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) Rsa {
    return NewRsa().FromPKCS8PublicKey(key)
}

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func GenerateKey(bits int) Rsa {
    return NewRsa().GenerateKey(bits)
}

// ==========

// Pkcs1
func FromPKCS1PrivateKey(key []byte) Rsa {
    return NewRsa().FromPKCS1PrivateKey(key)
}

// Pkcs1WithPassword
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPKCS1PrivateKeyWithPassword(key, password)
}

// Pkcs8
func FromPKCS8PrivateKey(key []byte) Rsa {
    return NewRsa().FromPKCS8PrivateKey(key)
}

// Pkcs8WithPassword
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPKCS8PrivateKeyWithPassword(key, password)
}

// Pkcs12 Cert
func FromPKCS12Cert(key []byte) Rsa {
    return NewRsa().FromPKCS12Cert(key)
}

// Pkcs12CertWithPassword
func FromPKCS12CertWithPassword(key []byte, password string) Rsa {
    return NewRsa().FromPKCS12CertWithPassword(key, password)
}

// ==========

// 字节
func FromBytes(data []byte) Rsa {
    return NewRsa().FromBytes(data)
}

// 字符
func FromString(data string) Rsa {
    return NewRsa().FromString(data)
}

// Base64
func FromBase64String(data string) Rsa {
    return NewRsa().FromBase64String(data)
}

// Hex
func FromHexString(data string) Rsa {
    return NewRsa().FromHexString(data)
}
