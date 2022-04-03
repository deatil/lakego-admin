package hash

// 字节
func (this Hash) FromBytes(data ...[]byte) Hash {
    return this.WithData(data...)
}

// 字符
func (this Hash) FromString(data string) Hash {
    return this.WithData([]byte(data))
}

// Base64
func (this Hash) FromBase64String(data string) Hash {
    newData, err := this.Base64Decode(data)

    this.Error = err

    return this.WithData(newData)
}

// Hex
func (this Hash) FromHexString(data string) Hash {
    newData, err := this.HexDecode(data)

    this.Error = err

    return this.WithData(newData)
}
