package hash

// 输出原始字符
func (this Hash) String() string {
    if len(this.data) == 0 {
        return ""
    }

    res := ""
    for _, data := range this.data {
        res += string(data)
    }

    return res
}

// 输出字节
func (this Hash) ToBytes() []byte {
    return []byte(this.hashedData)
}

// 输出字符
func (this Hash) ToString() string {
    return this.hashedData
}

// 输出Base64
func (this Hash) ToBase64String() string {
    return this.Base64Encode([]byte(this.hashedData))
}

// 输出Hex
func (this Hash) ToHexString() string {
    return this.HexEncode([]byte(this.hashedData))
}
