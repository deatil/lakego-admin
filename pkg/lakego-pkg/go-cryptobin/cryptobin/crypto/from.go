package crypto

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 设置数据字节
// set data bytes
func (this Cryptobin) FromBytes(data []byte) Cryptobin {
    this.data = data

    return this
}

// 设置数据字节
// set data bytes
func FromBytes(data []byte) Cryptobin {
    return defaultCryptobin.FromBytes(data)
}

// 设置数据字符
// set data string
func (this Cryptobin) FromString(data string) Cryptobin {
    this.data = []byte(data)

    return this
}

// 设置数据字符
// set data string
func FromString(data string) Cryptobin {
    return defaultCryptobin.FromString(data)
}

// 设置数据 Base64
// set data Base64
func (this Cryptobin) FromBase64String(data string) Cryptobin {
    newData, err := encoding.Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// 设置数据 Base64
// set data Base64
func FromBase64String(data string) Cryptobin {
    return defaultCryptobin.FromBase64String(data)
}

// 设置数据 Hex
// set data Hex
func (this Cryptobin) FromHexString(data string) Cryptobin {
    newData, err := encoding.HexDecode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
}

// 设置数据 Hex
// set data Hex
func FromHexString(data string) Cryptobin {
    return defaultCryptobin.FromHexString(data)
}
