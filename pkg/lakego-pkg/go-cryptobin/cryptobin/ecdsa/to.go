package ecdsa

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this ECDSA) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this ECDSA) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this ECDSA) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this ECDSA) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this ECDSA) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this ECDSA) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this ECDSA) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this ECDSA) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
