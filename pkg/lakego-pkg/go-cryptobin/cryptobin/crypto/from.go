package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

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
    newData, err := tool.NewEncoding().Base64Decode(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.data = newData

    return this
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
