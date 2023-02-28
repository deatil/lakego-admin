package dsa

// 构造函数
func NewDSA() DSA {
    return DSA{
        signHash: "SHA512",
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() DSA {
    return NewDSA()
}

// ==========

// 私钥
func FromPrivateKey(key []byte) DSA {
    return NewDSA().FromPrivateKey(key)
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) DSA {
    return NewDSA().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) DSA {
    return NewDSA().FromPublicKey(key)
}

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func GenerateKey(ln string) DSA {
    return NewDSA().GenerateKey(ln)
}

// ==========

// PKCS8 私钥
func FromPKCS8PrivateKey(key []byte) DSA {
    return NewDSA().FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func FromPKCS8PrivateKeyWithPassword(key []byte, password string) DSA {
    return NewDSA().FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func FromPKCS8PublicKey(key []byte) DSA {
    return NewDSA().FromPKCS8PublicKey(key)
}

// ==========

// 字节
func FromBytes(data []byte) DSA {
    return NewDSA().FromBytes(data)
}

// 字符
func FromString(data string) DSA {
    return NewDSA().FromString(data)
}

// Base64
func FromBase64String(data string) DSA {
    return NewDSA().FromBase64String(data)
}

// Hex
func FromHexString(data string) DSA {
    return NewDSA().FromHexString(data)
}
