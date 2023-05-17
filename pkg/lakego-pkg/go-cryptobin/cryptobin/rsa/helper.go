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

var (
    // 默认
    defaultRSA = NewRsa()
)

// ==========

// 私钥
func FromPrivateKey(key []byte) Rsa {
    return defaultRSA.FromPrivateKey(key)
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) Rsa {
    return defaultRSA.FromPublicKey(key)
}

// ==========

// 生成密钥
// bits = 512 | 1024 | 2048 | 4096
func GenerateKey(bits int) Rsa {
    return defaultRSA.GenerateKey(bits)
}

// 生成密钥
func GenerateMultiPrimeKey(nprimes int, bits int) Rsa {
    return defaultRSA.GenerateMultiPrimeKey(nprimes, bits)
}

// ==========

// PKCS1 私钥
func FromPKCS1PrivateKey(key []byte) Rsa {
    return defaultRSA.FromPKCS1PrivateKey(key)
}

// PKCS1 私钥带密码
func FromPKCS1PrivateKeyWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPKCS1PrivateKeyWithPassword(key, password)
}

// PKCS1 公钥
func FromPKCS1PublicKey(key []byte) Rsa {
    return defaultRSA.FromPKCS1PublicKey(key)
}

// ==========

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) Rsa {
    return defaultRSA.FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) Rsa {
    return defaultRSA.FromPKCS8PublicKey(key)
}

// ==========

// XML 私钥
func FromXMLPrivateKey(key []byte) Rsa {
    return defaultRSA.FromXMLPrivateKey(key)
}

// XML 公钥
func FromXMLPublicKey(key []byte) Rsa {
    return defaultRSA.FromXMLPublicKey(key)
}

// ==========

// Pkcs12Cert
func FromPKCS12Cert(key []byte) Rsa {
    return defaultRSA.FromPKCS12Cert(key)
}

// Pkcs12Cert 带密码
func FromPKCS12CertWithPassword(key []byte, password string) Rsa {
    return defaultRSA.FromPKCS12CertWithPassword(key, password)
}

// ==========

// 字节
func FromBytes(data []byte) Rsa {
    return defaultRSA.FromBytes(data)
}

// 字符
func FromString(data string) Rsa {
    return defaultRSA.FromString(data)
}

// Base64
func FromBase64String(data string) Rsa {
    return defaultRSA.FromBase64String(data)
}

// Hex
func FromHexString(data string) Rsa {
    return defaultRSA.FromHexString(data)
}
