package cryptobin

// 字节
func FromByte(data []byte) Crypto {
    return New().FromByte(data)
}

// 字符
func FromString(data string) Crypto {
    return New().FromString(data)
}

// Base64
func FromBase64String(data string) Crypto {
    return New().FromBase64(data)
}

// Hex
func FromHexString(data string) Crypto {
    return New().FromHex(data)
}
