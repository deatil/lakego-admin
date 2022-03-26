package cryptobin

// 输出原始字符
func (this Crypto) String() string {
    return string(this.Data)
}

// 输出字节
func (this Crypto) ToByte() []byte {
    return this.ParsedData
}

// 输出字符
func (this Crypto) ToString() string {
    return string(this.ParsedData)
}

// 输出Base64
func (this Crypto) ToBase64String() string {
    return this.Base64Encode(this.ParsedData)
}

// 输出Hex
func (this Crypto) ToHexString() string {
    return this.HexEncode(this.ParsedData)
}
