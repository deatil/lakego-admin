package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 输出原始字符
// output String
func (this Cryptobin) String() string {
    return string(this.data)
}

// 输出字节
// output Bytes
func (this Cryptobin) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
// output String
func (this Cryptobin) ToString() string {
    return string(this.parsedData)
}

// 输出 Base64
// output Base64 String
func (this Cryptobin) ToBase64String() string {
    return tool.Base64Encode(this.parsedData)
}

// 输出 Hex
// output Hex String
func (this Cryptobin) ToHexString() string {
    return tool.HexEncode(this.parsedData)
}
