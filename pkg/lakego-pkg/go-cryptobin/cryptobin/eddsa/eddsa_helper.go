package eddsa

// 构造函数
func NewEdDSA() EdDSA {
    return EdDSA{
        verify: false,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() EdDSA {
    return NewEdDSA()
}

// ==========

// 私钥
func FromPrivateKey(key []byte) EdDSA {
    return NewEdDSA().FromPrivateKey(key)
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) EdDSA {
    return NewEdDSA().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) EdDSA {
    return NewEdDSA().FromPublicKey(key)
}

// 生成密钥
func GenerateKey() EdDSA {
    return NewEdDSA().GenerateKey()
}

// ==========

// 字节
func FromBytes(data []byte) EdDSA {
    return NewEdDSA().FromBytes(data)
}

// 字符
func FromString(data string) EdDSA {
    return NewEdDSA().FromString(data)
}

// Base64
func FromBase64String(data string) EdDSA {
    return NewEdDSA().FromBase64String(data)
}

// Hex
func FromHexString(data string) EdDSA {
    return NewEdDSA().FromHexString(data)
}
