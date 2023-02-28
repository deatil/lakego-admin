package sm2

// 构造函数
func NewSM2() SM2 {
    return SM2{
        mode:   0,
        verify: false,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() SM2 {
    return NewSM2()
}

// ==========

// 私钥
func FromPrivateKey(key []byte) SM2 {
    return NewSM2().FromPrivateKey(key)
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password string) SM2 {
    return NewSM2().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) SM2 {
    return NewSM2().FromPublicKey(key)
}

// 生成密钥
func GenerateKey() SM2 {
    return NewSM2().GenerateKey()
}

// ==========

// 字节
func FromBytes(data []byte) SM2 {
    return NewSM2().FromBytes(data)
}

// 字符
func FromString(data string) SM2 {
    return NewSM2().FromString(data)
}

// Base64
func FromBase64String(data string) SM2 {
    return NewSM2().FromBase64String(data)
}

// Hex
func FromHexString(data string) SM2 {
    return NewSM2().FromHexString(data)
}
