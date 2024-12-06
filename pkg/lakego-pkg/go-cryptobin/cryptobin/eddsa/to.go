package eddsa

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this EdDSA) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this EdDSA) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this EdDSA) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this EdDSA) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this EdDSA) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this EdDSA) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this EdDSA) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this EdDSA) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
