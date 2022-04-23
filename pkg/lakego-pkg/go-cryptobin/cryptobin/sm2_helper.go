package cryptobin

// 私钥
func SM2FromPrivateKey(key []byte) SM2 {
    return NewSM2().FromPrivateKey(key)
}

// 私钥带密码
func SM2FromPrivateKeyWithPassword(key []byte, password string) SM2 {
    return NewSM2().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func SM2FromPublicKey(key []byte) SM2 {
    return NewSM2().FromPublicKey(key)
}

// 生成密钥
func SM2GenerateKey() SM2 {
    return NewSM2().GenerateKey()
}

// ==========

// 字节
func SM2FromBytes(data []byte) SM2 {
    return NewSM2().FromBytes(data)
}

// 字符
func SM2FromString(data string) SM2 {
    return NewSM2().FromString(data)
}

// Base64
func SM2FromBase64String(data string) SM2 {
    return NewSM2().FromBase64String(data)
}

// Hex
func SM2FromHexString(data string) SM2 {
    return NewSM2().FromHexString(data)
}
