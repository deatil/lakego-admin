package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 输出原始字符
func (this Cryptobin) String() string {
    return string(this.data)
}

// 输出字节
func (this Cryptobin) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this Cryptobin) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this Cryptobin) ToBase64String() string {
    return tool.Base64Encode(this.parsedData)
}

// 输出Hex
func (this Cryptobin) ToHexString() string {
    return tool.HexEncode(this.parsedData)
}
