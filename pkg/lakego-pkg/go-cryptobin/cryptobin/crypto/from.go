package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 字节
func (this Cryptobin) FromBytes(data []byte) Cryptobin {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Cryptobin {
    return defaultCryptobin.FromBytes(data)
}

// 字符
func (this Cryptobin) FromString(data string) Cryptobin {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Cryptobin {
    return defaultCryptobin.FromString(data)
}

// Base64
func (this Cryptobin) FromBase64String(data string) Cryptobin {
    newData, err := tool.NewEncoding().Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Base64
func FromBase64String(data string) Cryptobin {
    return defaultCryptobin.FromBase64String(data)
}

// Hex
func (this Cryptobin) FromHexString(data string) Cryptobin {
    newData, err := tool.NewEncoding().HexDecode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// Hex
func FromHexString(data string) Cryptobin {
    return defaultCryptobin.FromHexString(data)
}
