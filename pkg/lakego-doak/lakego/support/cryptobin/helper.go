package cryptobin

// 字节
func FromByte(data []byte) Cryptobin {
    return New().FromByte(data)
}

// 字符
func FromString(data string) Cryptobin {
    return New().FromString(data)
}

// Base64
func FromBase64String(data string) Cryptobin {
    return New().FromBase64String(data)
}

// Hex
func FromHexString(data string) Cryptobin {
    return New().FromHexString(data)
}
