package ecgdsa

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this SSH) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this SSH) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this SSH) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this SSH) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this SSH) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this SSH) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this SSH) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this SSH) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
