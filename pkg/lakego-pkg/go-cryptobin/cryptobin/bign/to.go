package bign

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this Bign) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Bign) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this Bign) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this Bign) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this Bign) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this Bign) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this Bign) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this Bign) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
