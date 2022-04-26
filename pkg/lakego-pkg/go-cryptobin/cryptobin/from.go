package cryptobin

// 字节
func (this Cryptobin) FromBytes(data []byte) Cryptobin {
    this.data = data

    return this
}

// 字符
func (this Cryptobin) FromString(data string) Cryptobin {
    this.data = []byte(data)

    return this
}

// Base64
func (this Cryptobin) FromBase64String(data string) Cryptobin {
    this.data, this.Error = NewEncoding().Base64Decode(data)

    return this
}

// Hex
func (this Cryptobin) FromHexString(data string) Cryptobin {
    this.data, this.Error = NewEncoding().HexDecode(data)

    return this
}
