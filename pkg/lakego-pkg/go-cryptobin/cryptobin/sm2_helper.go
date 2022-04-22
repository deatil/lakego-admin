package cryptobin

// 生成密钥
func SM2GenerateKey() SM2 {
    return NewSM2().GenerateKey()
}

// Pkcs8
func SM2FromSM2PrivateKey(key []byte) SM2 {
    return NewSM2().FromSM2PrivateKey(key)
}

// Pkcs8WithPassword
func SM2FromSM2PrivateKeyWithPassword(key []byte, password string) SM2 {
    return NewSM2().FromSM2PrivateKeyWithPassword(key, password)
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
