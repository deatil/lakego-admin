package ed448

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this ED448) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this ED448) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this ED448) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this ED448) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this ED448) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this ED448) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this ED448) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this ED448) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
