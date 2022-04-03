package hash

// 字节
func FromBytes(data ...[]byte) Hash {
    return NewHash().FromBytes(data...)
}

// 字符
func FromString(data string) Hash {
    return NewHash().FromString(data)
}

// Base64
func FromBase64String(data string) Hash {
    return NewHash().FromBase64String(data)
}

// Hex
func FromHexString(data string) Hash {
    return NewHash().FromHexString(data)
}
