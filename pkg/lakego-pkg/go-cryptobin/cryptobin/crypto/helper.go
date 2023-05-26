package crypto

// 字节
func FromBytes(data []byte) Cryptobin {
    return NewCryptobin().FromBytes(data)
}

// 字符
func FromString(data string) Cryptobin {
    return NewCryptobin().FromString(data)
}

// Base64
func FromBase64String(data string) Cryptobin {
    return NewCryptobin().FromBase64String(data)
}

// Hex
func FromHexString(data string) Cryptobin {
    return NewCryptobin().FromHexString(data)
}
