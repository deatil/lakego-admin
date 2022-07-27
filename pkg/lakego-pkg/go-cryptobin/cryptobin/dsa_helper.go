package cryptobin

// 构造函数
func NewDSA() DSA {
    return DSA{
        signHash: "SHA512",
        veryed:   false,
    }
}

// ==========

// 私钥
func DSAFromPrivateKey(key []byte) DSA {
    return NewDSA().FromPrivateKey(key)
}

// 私钥带密码
func DSAFromPrivateKeyWithPassword(key []byte, password string) DSA {
    return NewDSA().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func DSAFromPublicKey(key []byte) DSA {
    return NewDSA().FromPublicKey(key)
}

// 生成密钥
// 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
func DSAGenerateKey(ln string) DSA {
    return NewDSA().GenerateKey(ln)
}

// ==========

// PKCS8 私钥
func DSAFromPKCS8PrivateKey(key []byte) DSA {
    return NewDSA().FromPKCS8PrivateKey(key)
}

// PKCS8 私钥带密码
func DSAFromPKCS8PrivateKeyWithPassword(key []byte, password string) DSA {
    return NewDSA().FromPKCS8PrivateKeyWithPassword(key, password)
}

// PKCS8 公钥
func DSAFromPKCS8PublicKey(key []byte) DSA {
    return NewDSA().FromPKCS8PublicKey(key)
}

// ==========

// 字节
func DSAFromBytes(data []byte) DSA {
    return NewDSA().FromBytes(data)
}

// 字符
func DSAFromString(data string) DSA {
    return NewDSA().FromString(data)
}

// Base64
func DSAFromBase64String(data string) DSA {
    return NewDSA().FromBase64String(data)
}

// Hex
func DSAFromHexString(data string) DSA {
    return NewDSA().FromHexString(data)
}
