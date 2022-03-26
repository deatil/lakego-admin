package cryptobin

// 字节
func (this Crypto) FromByte(data []byte) Crypto {
    this.Data = data

    return this
}

// 字符
func (this Crypto) FromString(data string) Crypto {
    this.Data = []byte(data)

    return this
}

// Base64
func (this Crypto) FromBase64(data string) Crypto {
    this.Data, this.Error = this.Base64Decode(data)

    return this
}

// Hex
func (this Crypto) FromHex(data string) Crypto {
    this.Data, this.Error = this.HexDecode(data)

    return this
}
