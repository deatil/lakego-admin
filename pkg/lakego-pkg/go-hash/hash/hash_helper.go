package hash

// 构造函数
func New() Hash {
    return Hash{}
}

// 字节
func FromBytes(data ...[]byte) Hash {
    return New().FromBytes(data...)
}

// 字符
func FromString(data string) Hash {
    return New().FromString(data)
}

// Base64
func FromBase64String(data string) Hash {
    return New().FromBase64String(data)
}

// Hex
func FromHexString(data string) Hash {
    return New().FromHexString(data)
}
